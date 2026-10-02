# frozen_string_literal: true

require 'openssl'

class Net::SMTP
  # DNS-based Authentication of Named Entities (DANE) support for STARTTLS.
  module DANE
    SECURE = :secure
    INSECURE = :insecure
    BOGUS = :bogus
    AUTHENTICATED_NO_RECORDS = :authenticated_no_records

    class Error < ::StandardError; end

    class CapabilityError < Net::SMTPUnsupportedCommand; end

    class VerificationError < OpenSSL::SSL::SSLError; end

    class CertificateAssociationError < VerificationError; end

    class TrustPathError < VerificationError; end

    # A TLSA resource record: RFC 7671 sections 2.1.1 through 2.1.4.
    TLSA = Struct.new(:usage, :selector, :matching_type, :certificate_association_data, keyword_init: true)

    class Policy
      DOMAIN_ISSUED_CERTIFICATE_USAGE = 3

      DIGEST_CLASSES = {
        1 => OpenSSL::Digest::SHA256,
        2 => OpenSSL::Digest::SHA512,
      }.freeze

      attr_reader :authentication_status, :tlsa_rrset, :reference_domain

      def self.coerce_record(record)
        case record
        when TLSA
          record
        when Hash
          TLSA.new(record)
        when Array
          usage, selector, matching_type, certificate_association_data = record
          TLSA.new(usage: usage, selector: selector,
                   matching_type: matching_type,
                   certificate_association_data: certificate_association_data)
        else
          if record.respond_to?(:usage) && record.respond_to?(:selector) &&
             record.respond_to?(:matching_type) &&
             record.respond_to?(:certificate_association_data)
            TLSA.new(
              usage: record.usage,
              selector: record.selector,
              matching_type: record.matching_type,
              certificate_association_data: record.certificate_association_data)
          else
            raise ArgumentError, "unsupported TLSA record: #{record.inspect}"
          end
        end
      end

      def initialize(authentication_status, tlsa_rrset, reference_domain)
        @authentication_status = normalize_status(authentication_status)
        @tlsa_rrset = Array(tlsa_rrset).map { |record| self.class.coerce_record(record) }.freeze
        @reference_domain = String(reference_domain)
        raise ArgumentError, "reference_domain is required" if @reference_domain.empty?
      end

      def secure?
        @authentication_status == SECURE
      end

      def insecure?
        @authentication_status == INSECURE
      end

      def bogus?
        @authentication_status == BOGUS
      end

      def authenticated_no_records?
        @authentication_status == AUTHENTICATED_NO_RECORDS ||
          (secure? && @tlsa_rrset.empty?)
      end

      def usable_records
        @usable_records ||= @tlsa_rrset.select { |record| supported_record?(record) }
      end

      def unknown_records
        @unknown_records ||= @tlsa_rrset.reject { |record| supported_fields?(record) }
      end

      def malformed_records
        @malformed_records ||= @tlsa_rrset.select do |record|
          supported_fields?(record) && !valid_association_data?(record)
        end
      end

      def dane?
        secure? && !@tlsa_rrset.empty? && !usable_records.empty?
      end
      alias active? dane?

      def pkix?
        !dane?
      end

      def verify(chain, ssl_context = nil)
        unless secure?
          raise CertificateAssociationError,
                "DANE certificate association cannot be established for #{reference_domain}: " \
                "TLSA RRset is not authenticated by DNSSEC"
        end
        chain = Array(chain).compact
        if chain.empty?
          raise CertificateAssociationError,
                "DANE certificate association failed for #{reference_domain}: server presented no certificate"
        end

        leaf = chain.first
        path_failures = []

        usable_records.each do |record|
          candidate = candidate_certificate(record, chain)
          next unless candidate && association_match?(record, candidate)

          case record.usage
          when 0, 1
            if pkix_path_valid?(leaf, chain, ssl_context)
              return true
            end
            path_failures << record
          when 2
            if trust_anchor_path_valid?(leaf, chain, candidate)
              return true
            end
            path_failures << record
          when DOMAIN_ISSUED_CERTIFICATE_USAGE
            return true
          end
        end

        if path_failures.empty?
          raise CertificateAssociationError,
                "DANE certificate association failed for #{reference_domain}: " \
                "no presented certificate matched a usable TLSA record"
        end

        raise TrustPathError,
              "DANE trust path validation failed for #{reference_domain}: " \
              "matched TLSA record did not produce a valid certificate path"
      end

      private

      def normalize_status(status)
        case status.to_s
        when 'secure' then SECURE
        when 'insecure' then INSECURE
        when 'bogus' then BOGUS
        when 'authenticated_no_records' then AUTHENTICATED_NO_RECORDS
        else
          raise ArgumentError, "unsupported DNSSEC authentication status: #{status.inspect}"
        end
      end

      def supported_record?(record)
        supported_fields?(record) && valid_association_data?(record)
      end

      def supported_fields?(record)
        (0..3).cover?(Integer(record.usage)) &&
          (0..1).cover?(Integer(record.selector)) &&
          (0..2).cover?(Integer(record.matching_type))
      rescue ArgumentError, TypeError
        false
      end

      def valid_association_data?(record)
        data = normalized_data(record)
        return false unless data

        if record.matching_type == 0
          !data.empty?
        else
          data.bytesize == DIGEST_CLASSES.fetch(record.matching_type).new.digest_length
        end
      end

      def candidate_certificate(record, chain)
        case record.usage
        when 0
          chain.find { |certificate| association_match?(record, certificate) }
        when 1, DOMAIN_ISSUED_CERTIFICATE_USAGE
          chain.first
        when 2
          chain[1..]&.find { |certificate| association_match?(record, certificate) }
        end
      end

      def association_match?(record, certificate)
        expected = normalized_data(record)
        actual = selected_data(record.selector, certificate)
        return false unless expected && actual

        if record.matching_type == 0
          secure_compare(expected, actual)
        else
          digest = DIGEST_CLASSES.fetch(record.matching_type).digest(actual)
          secure_compare(expected, digest)
        end
      end

      def selected_data(selector, certificate)
        case selector
        when 0
          certificate.to_der
        when 1
          subject_public_key_info_der(certificate)
        end
      end

      def subject_public_key_info_der(certificate)
        OpenSSL::ASN1.decode(certificate.to_der).value[0].value[6].to_der
      rescue OpenSSL::ASN1::ASN1Error, NoMethodError
        certificate.public_key.public_to_der
      end

      def normalized_data(record)
        data = record.certificate_association_data
        case data
        when nil
          nil
        when Array
          return nil unless data.all? { |byte| byte.is_a?(Integer) && (0..255).cover?(byte) }
          data.pack('C*')
        when String
          normalize_string_data(record.matching_type, data)
        end
      end

      def normalize_string_data(matching_type, data)
        return data.b if matching_type == 0

        if data.ascii_only? && data.match?(/\A(?:[0-9a-fA-F]{2})+\z/)
          [data].pack('H*')
        else
          data.b
        end
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize
        return left == right unless OpenSSL.respond_to?(:fixed_length_secure_compare)
        OpenSSL.fixed_length_secure_compare(left, right)
      rescue ArgumentError
        false
      end

      def pkix_path_valid?(leaf, chain, ssl_context)
        store = pkix_store(ssl_context)
        presented_chain = chain[1..] || []
        context = OpenSSL::X509::StoreContext.new(store, leaf, presented_chain)
        context.verify &&
          OpenSSL::SSL.verify_certificate_identity(leaf, reference_domain)
      rescue OpenSSL::OpenSSLError
        false
      end

      def pkix_store(ssl_context)
        if ssl_context&.cert_store
          ssl_context.cert_store
        else
          store = OpenSSL::X509::Store.new
          if ssl_context
            store.add_file(ssl_context.ca_file) if ssl_context.ca_file
            store.add_path(ssl_context.ca_path) if ssl_context.ca_path
            store.set_default_paths unless ssl_context.ca_file || ssl_context.ca_path
          else
            store.set_default_paths
          end
          store
        end
      end

      def trust_anchor_path_valid?(leaf, chain, anchor)
        store = OpenSSL::X509::Store.new
        store.add_cert(anchor)
        store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
        context = OpenSSL::X509::StoreContext.new(store, leaf, chain[1..] || [])
        context.verify
      rescue OpenSSL::OpenSSLError
        false
      end
    end
  end
end
