require 'net/smtp'
require 'securerandom'
require 'test/unit'

unless defined?(OpenSSL::VERSION)
  warn "#{__FILE__}: openssl library not loaded; skipping"
  return
end

module Net
  class TestDANE < Test::Unit::TestCase
    DOMAIN = "mx.example.net"

    def setup
      @root_key = generate_key
      @root = make_certificate("DANE Root", @root_key, nil, nil, ca: true)
      @intermediate_key = generate_key
      @intermediate = make_certificate("DANE Intermediate", @intermediate_key, @root, @root_key, ca: true)
      @leaf_key = generate_key
      @leaf = make_certificate(DOMAIN, @leaf_key, @intermediate, @intermediate_key)
      @other_key = generate_key
      @other = make_certificate("other.example.net", @other_key, @root, @root_key)
      @unrelated_key = generate_key
      @unrelated = make_certificate("Unrelated CA", @unrelated_key, nil, nil, ca: true)
      @chain = [@leaf, @intermediate, @root]
      @context = OpenSSL::SSL::SSLContext.new
      @context.cert_store = store_for(@root)
    end

    def test_error_classes_identify_failure_stage
      assert_operator(Net::SMTP::DANE::CapabilityError, :<, Net::SMTPUnsupportedCommand)
      assert_operator(Net::SMTP::DANE::CertificateAssociationError, :<, OpenSSL::SSL::SSLError)
      assert_operator(Net::SMTP::DANE::TrustPathError, :<, OpenSSL::SSL::SSLError)
    end

    def test_usage_0_matches_trusted_ca_after_pkix_path_validation
      record = tlsa(0, 0, 1, digest(@intermediate.to_der))
      policy = secure_policy([record])

      assert_predicate(policy, :dane?)
      assert_equal(true, policy.verify(@chain, @context))
    end

    def test_usage_1_matches_leaf_with_subject_public_key_info
      record = tlsa(1, 1, 1, digest(@leaf.public_key.public_to_der))

      assert_equal(true, secure_policy([record]).verify(@chain, @context))
    end

    def test_usage_2_matches_intermediate_as_trust_anchor
      record = tlsa(2, 0, 1, digest(@intermediate.to_der))

      assert_equal(true, secure_policy([record]).verify(@chain))
    end

    def test_usage_3_accepts_exact_leaf_without_pkix_trust_path
      record = tlsa(3, 0, 0, @leaf.to_der)

      assert_equal(true, secure_policy([record]).verify([@leaf]))
    end

    def test_usage_3_accepts_sha512_spki
      record = tlsa(3, 1, 2, OpenSSL::Digest::SHA512.digest(@leaf.public_key.public_to_der))

      assert_equal(true, secure_policy([record]).verify([@leaf]))
    end

    def test_usage_1_accepts_hex_encoded_association_data
      record = tlsa(1, 1, 1, digest(@leaf.public_key.public_to_der).unpack1("H*"))

      assert_equal(true, secure_policy([record]).verify(@chain, @context))
    end

    def test_usage_1_mismatch_is_certificate_association_failure
      record = tlsa(1, 0, 1, digest(@other.to_der))

      error = assert_raise(Net::SMTP::DANE::CertificateAssociationError) do
        secure_policy([record]).verify(@chain, @context)
      end
      assert_match(/certificate association/, error.message)
      assert_include(error.message, DOMAIN)
    end

    def test_usage_1_wrong_reference_domain_is_trust_path_failure
      record = tlsa(1, 0, 1, digest(@leaf.to_der))

      error = assert_raise(Net::SMTP::DANE::TrustPathError) do
        secure_policy([record], "wrong.example.net").verify(@chain, @context)
      end
      assert_match(/trust path/, error.message)
    end

    def test_usage_1_untrusted_path_is_trust_path_failure
      record = tlsa(1, 0, 1, digest(@leaf.to_der))

      error = assert_raise(Net::SMTP::DANE::TrustPathError) do
        secure_policy([record]).verify(@chain)
      end
      assert_match(/trust path/, error.message)
    end

    def test_usage_2_matched_cert_with_broken_chain_is_trust_path_failure
      record = tlsa(2, 0, 1, digest(@unrelated.to_der))

      error = assert_raise(Net::SMTP::DANE::TrustPathError) do
        secure_policy([record]).verify(@chain + [@unrelated])
      end
      assert_match(/trust path/, error.message)
    end

    def test_empty_secure_rrset_is_authenticated_no_records_and_uses_pkix
      policy = policy(:secure, [], DOMAIN)

      assert_predicate(policy, :authenticated_no_records?)
      assert_not_predicate(policy, :dane?)
      assert_predicate(policy, :pkix?)
    end

    def test_explicit_authenticated_no_records_uses_pkix
      policy = policy(:authenticated_no_records, [], DOMAIN)

      assert_predicate(policy, :authenticated_no_records?)
      assert_predicate(policy, :pkix?)
    end

    def test_unknown_algorithm_is_unusable_and_pkix_represents_dane_unavailable
      record = tlsa(3, 9, 1, "00")
      policy = secure_policy([record])

      assert_equal([record], policy.unknown_records)
      assert_empty(policy.usable_records)
      assert_not_predicate(policy, :dane?)
      assert_predicate(policy, :pkix?)
    end

    def test_bad_digest_length_is_malformed_and_unusable
      record = tlsa(3, 1, 1, "short")
      policy = secure_policy([record])

      assert_equal([record], policy.malformed_records)
      assert_empty(policy.usable_records)
    end

    def test_unauthenticated_record_is_not_a_trust_anchor
      record = tlsa(3, 0, 0, @leaf.to_der)
      policy = policy(:insecure, [record], DOMAIN)

      assert_not_predicate(policy, :dane?)
      error = assert_raise(Net::SMTP::DANE::CertificateAssociationError) do
        policy.verify([@leaf])
      end
      assert_match(/not authenticated by DNSSEC/, error.message)
    end

    def test_bogus_rrset_is_not_a_trust_anchor
      record = tlsa(3, 0, 0, @leaf.to_der)
      policy = policy(:bogus, [record], DOMAIN)

      assert_not_predicate(policy, :dane?)
      assert_raise(Net::SMTP::DANE::CertificateAssociationError) do
        policy.verify([@leaf])
      end
    end

    def test_one_valid_record_and_one_unknown_record_validates_with_dane
      valid = tlsa(3, 1, 1, digest(@leaf.public_key.public_to_der))
      unknown = tlsa(9, 0, 1, digest(@leaf.to_der))

      assert_equal(true, secure_policy([unknown, valid]).verify([@leaf]))
    end

    def test_missing_peer_certificate_is_certificate_association_failure
      assert_raise(Net::SMTP::DANE::CertificateAssociationError) do
        secure_policy([tlsa(3, 0, 0, @leaf.to_der)]).verify([])
      end
    end

    private

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
      unless ca
        certificate.add_extension(factory.create_extension("subjectAltName", "DNS:#{common_name}", false))
      end

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

    def digest(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def secure_policy(rrset, domain = DOMAIN)
      policy(:secure, rrset, domain)
    end

    def policy(status, rrset, domain = DOMAIN)
      Net::SMTP::DANE::Policy.new(status, rrset, domain)
    end

    def store_for(*certificates)
      store = OpenSSL::X509::Store.new
      certificates.each { |certificate| store.add_cert(certificate) }
      store
    end
  end
end
