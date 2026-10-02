# frozen_string_literal: true

require "net/smtp"
require "test/unit"

unless defined?(OpenSSL::VERSION)
  warn "#{__FILE__}: openssl library not loaded; skipping"
  return
end

module Net
  class TestSMTPDANE < Test::Unit::TestCase
    REFERENCE_HOSTNAME = "smtp.example.test"

    class MySMTP < SMTP
      attr_reader :__ssl_socket

      def initialize(socket, **kwargs)
        @fake_socket = socket
        super(kwargs.delete(:address) || REFERENCE_HOSTNAME, **kwargs)
      end

      def tcp_socket(*)
        @fake_socket
      end

      def ssl_socket(socket, context)
        @__ssl_socket = super
      end
    end

    def setup
      @root_key = OpenSSL::PKey::EC.generate("prime256v1")
      @root_cert = create_certificate(@root_key, "/CN=Test DANE Root CA", ca: true)
      @intermediate_key = OpenSSL::PKey::EC.generate("prime256v1")
      @intermediate_cert = create_certificate(
        @intermediate_key, "/CN=Test DANE Intermediate CA",
        issuer_key: @root_key, issuer_cert: @root_cert, ca: true
      )
      @broken_intermediate_cert = create_certificate(
        OpenSSL::PKey::EC.generate("prime256v1"), "/CN=Broken DANE Intermediate CA",
        issuer_key: @root_key, issuer_cert: @root_cert, ca: true
      )
      @leaf_key = OpenSSL::PKey::EC.generate("prime256v1")
      @leaf_cert = create_certificate(
        @leaf_key, "/CN=#{REFERENCE_HOSTNAME}",
        issuer_key: @intermediate_key, issuer_cert: @intermediate_cert
      )
      @other_key = OpenSSL::PKey::EC.generate("prime256v1")
      @other_cert = create_certificate(@other_key, "/CN=other.example.test")

      @store = OpenSSL::X509::Store.new
      @store.add_cert(@root_cert)
    end

    def teardown
      @server_thread&.join(0.1)
      @server_thread&.kill
      @server_socket&.close
      @client_socket&.close
    end

    def test_tlsa_usage_zero_requires_pkix_and_match
      assert_dane_accept(tlsa(usage: 0, selector: 0, matching_type: 1))
      socket = last_ssl_socket
      assert_equal(OpenSSL::SSL::VERIFY_NONE, socket.context.verify_mode)
      assert_equal(REFERENCE_HOSTNAME, socket.hostname)
    end

    def test_tlsa_usage_zero_may_match_pkix_trust_anchor
      assert_dane_accept(tlsa(usage: 0, selector: 0, matching_type: 1,
                               certificate: @root_cert))
    end

    def test_tlsa_usage_one_matches_public_key_after_pkix
      assert_dane_accept(tlsa(usage: 1, selector: 1, matching_type: 1))
    end

    def test_tlsa_usage_two_uses_authenticated_ca_anchor
      other_store = OpenSSL::X509::Store.new
      other_store.add_cert(@other_cert)
      assert_dane_accept(tlsa(usage: 2, selector: 0, matching_type: 1,
                               certificate: @intermediate_cert),
                         cert_store: other_store)
    end

    def test_tlsa_usage_two_accepts_root_trust_anchor
      assert_dane_accept(tlsa(usage: 2, selector: 0, matching_type: 1,
                               certificate: @root_cert))
    end

    def test_tlsa_usage_three_uses_authenticated_domain_anchor
      other_store = OpenSSL::X509::Store.new
      other_store.add_cert(@other_cert)
      assert_dane_accept(tlsa(usage: 3, selector: 1, matching_type: 2,
                               certificate: @leaf_cert),
                         cert_store: other_store)
    end

    def test_tlsa_full_certificate_selector_zero
      assert_dane_accept(tlsa(usage: 3, selector: 0, matching_type: 0))
    end

    def test_custom_callable_policy_can_verify_the_negotiated_socket
      policy = Object.new
      captured_socket = nil
      policy.define_singleton_method(:hostname) { REFERENCE_HOSTNAME }
      policy.define_singleton_method(:before_starttls) { }
      policy.define_singleton_method(:call) { |socket| captured_socket = socket }
      policy.define_singleton_method(:captured_socket) { captured_socket }

      smtp = start_with_dane(policy)
      assert_equal(REFERENCE_HOSTNAME, policy.captured_socket.hostname)
      assert(smtp.rset.success?)
    end

    def test_secure_empty_rrset_falls_back_to_pkix_with_name_checks
      assert_dane_accept(dane_policy(secure: true, tlsa: []))
    end

    def test_secure_empty_rrset_does_not_disable_pkix_name_checks
      policy = dane_policy(secure: true, tlsa: [], hostname: "other.example.test")
      error = assert_raise(SMTPDANETrustPathError) do
        start_with_dane(policy)
      end
      assert_match(/certificate does not match reference hostname/, error.message)
    end

    def test_dane_ignores_tls_verify_false_for_pkix_name_checks
      policy = dane_policy(secure: true, tlsa: [], hostname: "other.example.test")
      error = assert_raise(SMTPDANETrustPathError) do
        smtp = MySMTP.new(start_smtpd(true), tls_verify: false, dane: policy)
        smtp.start
      end
      assert_match(/certificate does not match reference hostname/, error.message)
    end

    def test_secure_empty_rrset_rejects_untrusted_pkix_path
      policy = dane_policy(secure: true, tlsa: [],
                           cert_store: OpenSSL::X509::Store.new)
      error = assert_raise(SMTPDANETrustPathError) do
        start_with_dane(policy)
      end
      assert_match(/PKIX certificate verification failed/, error.message)
    end

    def test_insecure_records_are_not_trust_anchors
      record = tlsa(usage: 3, selector: 0, matching_type: 0)
      policy = dane_policy(secure: false, tlsa: [record],
                           cert_store: OpenSSL::X509::Store.new)
      error = assert_raise(SMTPDANETrustPathError) do
        start_with_dane(policy)
      end
      assert_match(/DNSSEC-unauthenticated TLSA records were ignored/, error.message)
      assert_match(/PKIX certificate verification failed/, error.message)
    end

    def test_insecure_records_still_allow_trusted_pkix
      assert_dane_accept(dane_policy(secure: false, tlsa: [tlsa(usage: 3)]))
    end

    def test_bogus_dnssec_fails_capability_phase_before_tls
      policy = dane_policy(secure: :bogus, tlsa: [tlsa(usage: 3)])
      error = assert_raise(SMTPDANEDNSAuthenticationError) do
        start_with_dane(policy)
      end
      assert_match(/bogus DNSSEC response/, error.message)
    end

    def test_association_failure_is_not_plain_tls_fallback
      record = tlsa(usage: 3, selector: 0, matching_type: 1,
                    certificate: @other_cert)
      error = assert_raise(SMTPDANECertificateAssociationError) do
        start_with_dane(tlsa_records: [record], cert_store: @store)
      end
      assert_match(/no certificate matched TLSA record/, error.message)
    end

    def test_unknown_algorithm_records_are_rejected
      record = tlsa(usage: 9, selector: 0, matching_type: 1)
      error = assert_raise(SMTPDANEUnsupportedTLSAError) do
        start_with_dane(tlsa_records: [record], cert_store: @store)
      end
      assert_match(/no usable TLSA records/, error.message)
      assert_match(/unknown usage 9/, error.message)
    end

    def test_unknown_selector_is_ignored_when_a_usable_record_exists
      records = [
        tlsa(usage: 9, selector: 0, matching_type: 1),
        tlsa(usage: 3, selector: 0, matching_type: 0)
      ]
      assert_dane_accept(records: records)
    end

    def test_usage_two_trust_path_failure
      record = tlsa(usage: 2, selector: 0, matching_type: 1,
                    certificate: @broken_intermediate_cert)
      broken_store = OpenSSL::X509::Store.new
      broken_store.add_cert(@other_cert)
      error = assert_raise(SMTPDANETrustPathError) do
        start_with_dane(tlsa_records: [record], cert_store: broken_store)
      end
      assert_match(/TLSA usage 2 trust path failure/, error.message)
    end

    def test_usage_two_requires_ca_certificate
      record = tlsa(usage: 2, selector: 0, matching_type: 1,
                    certificate: @leaf_cert)
      error = assert_raise(SMTPDANETrustPathError) do
        start_with_dane(tlsa_records: [record], cert_store: @store)
      end
      assert_match(/matched certificate is not a CA certificate/, error.message)
    end

    def test_tlsa_accepts_stringified_hash_and_hex_data
      raw = @leaf_cert.to_der
      record = {
        "usage" => 3,
        "selector" => 0,
        "matching_type" => 0,
        "data" => raw.unpack1("H*")
      }
      assert_dane_accept(records: [SMTP::DANE::TLSA.new(record)])
    end

    def test_policy_accepts_positional_arguments_and_duck_typed_status
      result = Struct.new(:rrset) do
        def secure?
          true
        end

        def bogus?
          false
        end
      end.new([tlsa(usage: 3)])
      policy = SMTP::DANE.new(REFERENCE_HOSTNAME, result, result.rrset)
      assert_equal(:secure, policy.authentication_status)
      assert_dane_accept(policy)
    end

    def test_policy_accepts_structured_tlsa_records
      data = OpenSSL::Digest::SHA256.digest(@leaf_cert.to_der)
      record = Struct.new(:certificate_usage, :selector,
                          :matching_type, :certificate_association_data).new(3, 0, 1, data)
      assert_dane_accept(records: [record])
    end

    def test_capability_failure_when_starttls_is_not_advertised
      policy = dane_policy(secure: true, tlsa: [tlsa(usage: 3)])
      error = assert_raise(SMTPDANECapabilityError) do
        start_with_dane(policy, starttls_capable: false)
      end
      assert_match(/STARTTLS capability/, error.message)
    end

    def test_capability_failure_when_starttls_is_refused
      policy = dane_policy(secure: true, tlsa: [tlsa(usage: 3)])
      error = assert_raise(SMTPDANECapabilityError) do
        start_with_dane(policy, starttls_capable: :refused)
      end
      assert_match(/server refused STARTTLS/, error.message)
    end

    def test_dane_rejects_explicit_plaintext
      error = assert_raise(ArgumentError) do
        SMTP.new(REFERENCE_HOSTNAME, starttls: false,
                 dane: dane_policy(secure: true, tlsa: []))
      end
      assert_equal("DANE is only supported with STARTTLS", error.message)
    end

    def test_dane_rejects_smtps
      error = assert_raise(ArgumentError) do
        SMTP.new(REFERENCE_HOSTNAME, tls: true,
                 dane: dane_policy(secure: true, tlsa: []))
      end
      assert_equal("DANE is only supported with STARTTLS", error.message)
    end

    private

    def assert_dane_accept(policy_or_records = nil, **kwargs)
      if policy_or_records.is_a?(SMTP::DANE)
        smtp = start_with_dane(policy_or_records)
      else
        smtp = start_with_dane(tlsa_records: policy_or_records, **kwargs)
      end
      assert(smtp.rset.success?)
      smtp
    end

    def start_with_dane(policy = nil, starttls_capable: true, **policy_options)
      policy ||= dane_policy(**policy_options)
      smtp = MySMTP.new(start_smtpd(starttls_capable), dane: policy)
      smtp.start
      @smtp = smtp
      smtp
    end

    def dane_policy(records: nil, tlsa_records: nil, secure: true,
                    hostname: REFERENCE_HOSTNAME, cert_store: @store, **kwargs)
      records ||= tlsa_records || [tlsa(usage: 3, selector: 0, matching_type: 0)]
      SMTP::DANE.new(
        hostname: hostname,
        authentication_status: secure == true ? :secure : (secure == false ? :insecure : secure),
        tlsa: records,
        cert_store: cert_store,
        **kwargs
      )
    end

    def tlsa(usage:, selector: 0, matching_type: 1, certificate: @leaf_cert)
      value = if selector == 1
                 certificate.public_key.respond_to?(:public_to_der) ?
                   certificate.public_key.public_to_der :
                   OpenSSL::ASN1.decode(certificate.to_der).value[0].value[6].to_der
               else
                 certificate.to_der
               end
      data = case matching_type
             when 0 then value
             when 1 then OpenSSL::Digest::SHA256.digest(value)
             when 2 then OpenSSL::Digest::SHA512.digest(value)
             end
      SMTP::DANE::TLSA.new(usage, selector, matching_type, data)
    end

    def last_ssl_socket
      @smtp.__ssl_socket
    end

    def start_smtpd(capable)
      @client_socket, @server_socket = Object.const_defined?(:UNIXSocket) ?
        UNIXSocket.pair : Socket.pair(:INET, :STREAM, 0)
      @server_thread = Thread.new(@server_socket) do |socket|
        socket.puts "220 fakeserver\r\n"
        while command = socket.gets&.chomp
          case command
          when /\AEHLO /
            socket.puts "250-fakeserver\r\n"
            socket.puts "250-STARTTLS\r\n" if capable
            socket.puts "250 8BITMIME\r\n"
          when /\ARSET/
            socket.puts "250 OK\r\n"
          when /\ASTARTTLS/
            if capable == :refused
              socket.puts "502 STARTTLS refused\r\n"
            else
              socket.puts "220 2.0.0 Ready to start TLS\r\n"
            end
            socket = wrap_server_ssl(socket)
            break unless socket
          else
            raise "unsupported command: #{command}"
          end
        end
      end
      @client_socket
    end

    def wrap_server_ssl(socket)
      context = OpenSSL::SSL::SSLContext.new
      context.add_certificate(@leaf_cert, @leaf_key,
                               [@intermediate_cert, @broken_intermediate_cert])
      server = OpenSSL::SSL::SSLSocket.new(socket, context)
      server.sync_close = true
      server.accept
    rescue OpenSSL::SSL::SSLError, SystemCallError, IOError
      nil
    end

    def create_certificate(key, subject, issuer_key: key, issuer_cert: nil, ca: false)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = OpenSSL::BN.rand(128)
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 3600
      certificate.public_key = key
      certificate.subject = OpenSSL::X509::Name.parse(subject)
      certificate.issuer = issuer_cert ? issuer_cert.subject : certificate.subject
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = certificate
      extension_factory.issuer_certificate = issuer_cert || certificate
      certificate.extensions = [
        extension_factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE"),
        extension_factory.create_extension("keyUsage", ca ? "keyCertSign,cRLSign" : "digitalSignature,keyEncipherment"),
      ]
      if subject.include?(REFERENCE_HOSTNAME)
        certificate.add_extension(
          extension_factory.create_extension("subjectAltName", "DNS:#{REFERENCE_HOSTNAME}", false)
        )
      end
      certificate.sign(issuer_key, OpenSSL::Digest::SHA256.new)
      certificate
    end
  end
end
