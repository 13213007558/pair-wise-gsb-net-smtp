require 'net/smtp'
require 'securerandom'
require 'test/unit'

unless defined?(OpenSSL::VERSION)
  warn "#{__FILE__}: openssl library not loaded; skipping"
  return
end

module Net
  class TestDANEStartTLS < Test::Unit::TestCase
    REFERENCE_DOMAIN = "mx.example.net"
    CONNECTION_NAME = "connection.example"

    class MySMTP < SMTP
      attr_reader :__ssl_context, :__ssl_socket

      def initialize(socket, address: CONNECTION_NAME, **options)
        @fake_socket = socket
        super(address, **options)
      end

      def tcp_socket(*)
        @fake_socket
      end

      def ssl_socket(socket, context)
        @__ssl_context = context
        @__ssl_socket = super
      end
    end

    def setup
      @root_key = generate_key
      @root = make_certificate("DANE STARTTLS Root", @root_key, nil, nil, ca: true)
      @intermediate_key = generate_key
      @intermediate = make_certificate("DANE STARTTLS Intermediate", @intermediate_key, @root, @root_key, ca: true)
      @leaf_key = generate_key
      @leaf = make_certificate(REFERENCE_DOMAIN, @leaf_key, @intermediate, @intermediate_key)
    end

    def teardown
      @server_thread&.exit&.join
      @server_socket&.close
      @client_socket&.close
    end

    def test_usage_3_validates_without_pkix_and_uses_reference_domain_for_sni
      rrset = [tlsa(3, 1, 1, sha256(@leaf.public_key.public_to_der))]
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:secure, rrset, REFERENCE_DOMAIN))

      smtp.start

      assert_equal(REFERENCE_DOMAIN, smtp.__ssl_socket.hostname)
      assert_equal(OpenSSL::SSL::VERIFY_PEER, smtp.__ssl_context.verify_mode)
      assert_equal(false, smtp.__ssl_context.verify_hostname)
      assert(smtp.rset.success?)
    end

    def test_usage_2_accepts_intermediate_as_trust_anchor
      rrset = [tlsa(2, 0, 1, sha256(@intermediate.to_der))]
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:secure, rrset, REFERENCE_DOMAIN))

      smtp.start
      assert(smtp.rset.success?)
    end

    def test_usage_3_mismatch_is_certificate_association_error_and_closes_tls
      rrset = [tlsa(3, 0, 1, sha256(@root.to_der))]
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:secure, rrset, REFERENCE_DOMAIN))

      error = assert_raise(Net::SMTP::DANE::CertificateAssociationError) { smtp.start }
      assert_match(/certificate association/, error.message)
      assert_equal(true, smtp.__ssl_socket.closed?)
    end

    def test_authenticated_no_records_falls_back_to_pkix_without_downgrading_tls
      context = trusted_context
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:authenticated_no_records, [], REFERENCE_DOMAIN))
      smtp.enable_starttls(context)

      smtp.start

      assert_equal(OpenSSL::SSL::VERIFY_PEER, context.verify_mode)
      assert_equal(true, context.verify_hostname)
      assert(smtp.rset.success?)
    end

    def test_secure_unknown_algorithm_falls_back_to_pkix
      context = trusted_context
      rrset = [tlsa(3, 9, 1, "00")]
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:secure, rrset, REFERENCE_DOMAIN))
      smtp.enable_starttls(context)

      smtp.start
      assert(smtp.rset.success?)
    end

    def test_unauthenticated_record_is_not_used_as_trust_anchor
      rrset = [tlsa(3, 1, 1, sha256(@leaf.public_key.public_to_der))]
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:insecure, rrset, REFERENCE_DOMAIN))

      assert_raise(OpenSSL::SSL::SSLError) { smtp.start }
      assert_equal(OpenSSL::SSL::VERIFY_PEER, smtp.__ssl_context.verify_mode)
      assert_equal(true, smtp.__ssl_context.verify_hostname)
    end

    def test_missing_starttls_advertisement_is_capability_error
      smtp = MySMTP.new(start_smtpd(starttls: false),
                        dane_policy: policy(:secure, [tlsa(3, 0, 0, @leaf.to_der)], REFERENCE_DOMAIN))

      error = assert_raise(Net::SMTP::DANE::CapabilityError) { smtp.start }
      assert_match(/STARTTLS capability negotiation failed/, error.message)
    end

    def test_dane_policy_cannot_be_weakened_after_construction
      smtp = MySMTP.new(start_smtpd(leaf: @leaf, key: @leaf_key),
                        dane_policy: policy(:secure, [tlsa(3, 0, 0, @leaf.to_der)], REFERENCE_DOMAIN))

      assert_raise(ArgumentError) { smtp.enable_tls }
      assert_raise(ArgumentError) { smtp.enable_starttls_auto }
      assert_raise(ArgumentError) { smtp.disable_starttls }
    end

    private

    def start_smtpd(starttls: true, leaf: @leaf, key: @leaf_key)
      @server_socket, @client_socket = Object.const_defined?(:UNIXSocket) ?
        UNIXSocket.pair : Socket.pair(:INET, :STREAM, 0)
      @server_thread = Thread.new(@server_socket, leaf, key) do |socket, presented_leaf, presented_key|
        socket.puts "220 fakeserver\r\n"
        while command = socket.gets&.chomp
          case command
          when /\AEHLO /
            socket.puts "250-fakeserver\r\n"
            socket.puts "250-STARTTLS\r\n" if starttls
            socket.puts "250 8BITMIME\r\n"
          when /\ARSET/
            socket.puts "250 OK\r\n"
          when /\ASTARTTLS/
            socket.puts "220 2.0.0 Ready to start TLS\r\n"
            socket = wrap_ssl_socket(socket, presented_leaf, presented_key) or break
          else
            raise "unsupported command: #{command}"
          end
        end
      end
      @client_socket
    end

    def wrap_ssl_socket(socket, leaf, key)
      context = OpenSSL::SSL::SSLContext.new
      context.add_certificate(leaf, key, leaf == @leaf ? [@intermediate] : [])
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl_socket.sync_close = true
      ssl_socket.accept
      ssl_socket
    rescue OpenSSL::SSL::SSLError, SystemCallError, IOError
      nil
    end

    def trusted_context
      store = OpenSSL::X509::Store.new
      store.add_cert(@root)
      context = OpenSSL::SSL::SSLContext.new
      context.cert_store = store
      context
    end

    def generate_key
      OpenSSL::PKey::EC.generate("prime256v1")
    end

    def make_certificate(common_name, key, issuer_certificate, issuer_key, ca: false)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = SecureRandom.random_number(1..0xffff_ffff)
      certificate.subject = OpenSSL::X509::Name.new([["CN", common_name]])
      certificate.issuer = issuer_certificate ? issuer_certificate.subject : certificate.subject
      certificate.public_key = key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 600

      factory = OpenSSL::X509::ExtensionFactory.new(issuer_certificate || certificate, certificate)
      certificate.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
      certificate.add_extension(factory.create_extension("keyUsage", ca ? "keyCertSign,cRLSign" : "digitalSignature", true))
      certificate.add_extension(factory.create_extension("subjectAltName", "DNS:#{common_name}", false)) unless ca
      certificate.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
      certificate
    end

    def tlsa(usage, selector, matching_type, data)
      Net::SMTP::DANE::TLSA.new(
        usage: usage,
        selector: selector,
        matching_type: matching_type,
        certificate_association_data: data)
    end

    def sha256(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def policy(status, rrset, domain)
      Net::SMTP::DANE::Policy.new(status, rrset, domain)
    end
  end
end
