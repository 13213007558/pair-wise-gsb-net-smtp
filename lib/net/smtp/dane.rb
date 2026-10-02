# frozen_string_literal: true

module Net
  class SMTP
    # DANE policy for verifying a STARTTLS server certificate with a
    # DNSSEC-authenticated TLSA RRset.
    class DANE
      SECURE_STATES = [:secure, :authenticated, :ad].freeze
      INSECURE_STATES = [:insecure, :unauthenticated].freeze
      BOGUS_STATES = [:bogus, :dnssec_bogus].freeze

      attr_reader :hostname, :tlsa, :authentication_status

      def initialize(hostname = nil, authentication_status = nil, tlsa_rrset_argument = nil, **options)
        keyword_hostname = options[:hostname] || options[:reference_hostname]
        @hostname = hostname unless hostname.is_a?(Hash)
        @hostname ||= keyword_hostname
        raise ArgumentError, "DANE reference hostname is required" if @hostname.nil? || @hostname.to_s.empty?

        if hostname.is_a?(Hash)
          options = hostname
          authentication_status = nil
          tlsa_rrset_argument = nil
        end

        authenticated = options.fetch(:authenticated, true)
        status = options[:authentication_status]
        status = options[:status] if status.nil?
        secure = options[:secure]
        dnssec_status = options[:dnssec_status]
        tlsa = options[:tlsa]
        tlsa_rrset = options[:tlsa_rrset]
        @cert_store = options[:cert_store]

        status_value =
          if !authentication_status.nil?
            authentication_status
          elsif !status.nil?
            status
          elsif !dnssec_status.nil?
            dnssec_status
          elsif !secure.nil?
            secure
          else
            authenticated
          end
        @authentication_status = normalize_status(status_value)
        records = tlsa_rrset_argument || tlsa || tlsa_rrset
        if records.nil?
          raise ArgumentError, "DANE TLSA RRset is required; use [] for authenticated no-data"
        end
        @tlsa = normalize_tlsa(records)
      end

      def secure?
        @authentication_status == :secure
      end

      def insecure?
        @authentication_status == :insecure
      end

      def bogus?
        @authentication_status == :bogus
      end

      def authenticated_no_data?
        secure? && @tlsa.empty?
      end

      def usable_records
        @tlsa.select(&:usable?)
      end

      def unknown_records
        @tlsa.reject(&:usable?)
      end

      def before_starttls
        raise SMTPDANEDNSAuthenticationError,
              "DANE cannot use a bogus DNSSEC response for #{@hostname}" if bogus?
      end

      def verify(socket)
        before_starttls

        certificate = socket.peer_cert
        unless certificate
          raise SMTPDANECertificateAssociationError,
                "DANE certificate association failure: STARTTLS server presented no certificate for #{@hostname}"
        end

        chain = socket.peer_cert_chain
        chain = [certificate] if chain.nil? || chain.empty?

        if insecure?
          return verify_pkix(socket, certificate, chain,
                             "DNSSEC-unauthenticated TLSA records were ignored")
        end
        return verify_pkix(socket, certificate, chain) if authenticated_no_data?
        raise SMTPDANEUnsupportedTLSAError, unsupported_records_message if usable_records.empty?

        association_errors = []
        trust_errors = []

        grouped_records = usable_records.group_by(&:usage)

        [0, 1].each do |usage|
          records = grouped_records[usage]
          next unless records

          pkix_error, pkix_chain = pkix_verification(socket, certificate, chain)
          if pkix_error
            trust_errors << "TLSA usage #{usage} requires PKIX validation: #{pkix_error}"
            next
          end

          records.each do |record|
            candidates = usage == 1 ? [certificate] : pkix_chain
            if record.matches_chain?(candidates)
              return true
            end
            association_errors << association_failure(record)
          end
        end

        [2, 3].each do |usage|
          records = grouped_records[usage]
          next unless records

          records.each do |record|
            matched_certificate = chain.find { |candidate| record.matches?(candidate) }
            unless matched_certificate
              if usage == 2
                pkix_error, pkix_chain = pkix_verification(socket, certificate, chain)
                if !pkix_error && record.matches_chain?(pkix_chain)
                  return true
                end
              end
              association_errors << association_failure(record)
              next
            end

            if usage == 2 && !record.ca_certificate?(matched_certificate)
              trust_errors << "TLSA usage 2 trust path failure: matched certificate is not a CA certificate"
              next
            end

            error = trust_anchor_verification_error(socket, certificate, chain, matched_certificate)
            if error
              trust_errors << "TLSA usage #{usage} trust path failure: #{error}"
            else
              return true
            end
          end
        end

        unless trust_errors.empty?
          raise SMTPDANETrustPathError,
                "DANE trust path failure for #{@hostname}: #{trust_errors.join('; ')}"
        end

        if association_errors.empty?
          raise SMTPDANEUnsupportedTLSAError, unsupported_records_message
        end

        raise SMTPDANECertificateAssociationError,
              "DANE certificate association failure for #{@hostname}: #{association_errors.join('; ')}"
      end

      # One TLSA record.
      class TLSA
        attr_reader :usage, :selector, :matching_type, :data

        def initialize(usage = nil, selector = nil, matching_type = nil, data = nil)
          if usage.respond_to?(:to_hash)
            record = usage.to_hash
            fetch = lambda do |*keys|
              keys.lazy.map do |key|
                if record.key?(key)
                  record[key]
                elsif record.key?(key.to_s)
                  record[key.to_s]
                elsif record.key?(key.to_sym)
                  record[key.to_sym]
                end
              end.first
            end
            usage = fetch.call(:usage, :certificate_usage)
            selector = fetch.call(:selector)
            matching_type = fetch.call(:matching_type, :match_type)
            data = fetch.call(:data, :certificate_association_data)
          elsif usage.respond_to?(:rdata)
            return initialize(usage.rdata)
          elsif usage.respond_to?(:certificate_usage)
            record = usage
            usage = record.certificate_usage
            selector = record.selector if selector.nil?
            matching_type = record.matching_type if matching_type.nil?
            data = record.certificate_association_data if data.nil?
          elsif usage.is_a?(String) && usage.match?(/\A\d+\s+\d+\s+\d+\s+[0-9a-fA-F\s]+\z/)
            usage, selector, matching_type, data = usage.split(nil, 4)
          end

          @usage = Integer(usage)
          @selector = Integer(selector)
          @matching_type = Integer(matching_type)
          @data = normalize_data(data)
        end

        def usable?
          (0..3).include?(@usage) && [0, 1].include?(@selector) && [0, 1, 2].include?(@matching_type)
        end

        def ca_certificate?(certificate)
          extension = certificate.extensions.find { |candidate| candidate.oid == "basicConstraints" }
          !!extension&.value&.include?("CA:TRUE")
        end

        def matches_chain?(chain)
          chain.any? { |certificate| matches?(certificate) }
        end

        def matches?(certificate)
          value = @selector == 0 ? certificate.to_der : subject_public_key_info(certificate)
          case @matching_type
          when 0
            value == @data
          when 1
            OpenSSL::Digest::SHA256.digest(value) == @data
          when 2
            OpenSSL::Digest::SHA512.digest(value) == @data
          end
        end

        def to_s
          "#{@usage} #{@selector} #{@matching_type} #{@data.unpack1('H*')}"
        end

        private

        def subject_public_key_info(certificate)
          if certificate.public_key.respond_to?(:public_to_der)
            certificate.public_key.public_to_der
          else
            OpenSSL::ASN1.decode(certificate.to_der).value[0].value[6].to_der
          end
        end

        def normalize_data(data)
          case data
          when nil
            raise ArgumentError, "TLSA certificate association data is required"
          when String
            if data.bytes.any? { |byte| !"0123456789abcdefABCDEF \t\r\n".bytes.include?(byte) }
              data.dup
            else
              hex = data.delete(' \t\r\n')
              unless hex.match?(/\A[0-9a-fA-F]*\z/)
                raise ArgumentError, "TLSA certificate association data must be hexadecimal"
              end
              [hex].pack("H*")
            end
          else
            data.to_str
          end
        end
      end

      private

      def normalize_status(status)
        case status
        when true, *SECURE_STATES
          :secure
        when false, *INSECURE_STATES
          :insecure
        when *BOGUS_STATES
          :bogus
        else
          if status.respond_to?(:bogus?) && status.bogus?
            :bogus
          elsif status.respond_to?(:secure?)
            status.secure? ? :secure : :insecure
          elsif status.respond_to?(:ad?)
            status.ad? ? :secure : :insecure
          else
            status = status.to_s.downcase.tr('-', '_').to_sym
            return :secure if SECURE_STATES.include?(status)
            return :insecure if INSECURE_STATES.include?(status)
            return :bogus if BOGUS_STATES.include?(status)

            raise ArgumentError, "unsupported DANE DNSSEC authentication status: #{status.inspect}"
          end
        end
      end

      def normalize_tlsa(records)
        case records
        when TLSA
          [records]
        when ->(value) { value.respond_to?(:certificate_usage) }
          [TLSA.new(records)]
        when ->(value) { value.respond_to?(:records) }
          normalize_tlsa(records.records)
        when ->(value) { !value.respond_to?(:to_hash) && value.respond_to?(:to_a) }
          records.to_a.flat_map { |record| normalize_tlsa(record) }
        when Array
          records.flat_map { |record| normalize_tlsa(record) }
        else
          [records].map { |record| record.is_a?(TLSA) ? record : TLSA.new(record) }
        end
      end

      def verify_pkix(socket, certificate, chain, reason = nil)
        error, = pkix_verification(socket, certificate, chain)
        if error
          detail = reason ? "#{reason}; " : ""
          raise SMTPDANETrustPathError,
                "DANE trust path failure for #{@hostname}: #{detail}#{error}"
        end
        true
      end

      def pkix_verification(socket, certificate, chain)
        store = certificate_store(socket)
        context = OpenSSL::X509::StoreContext.new(store, certificate, chain.drop(1))
        unless context.verify
          return ["PKIX certificate verification failed: #{context.error_string || 'unknown error'}", chain]
        end

        unless OpenSSL::SSL.verify_certificate_identity(certificate, @hostname)
          return ["certificate does not match reference hostname #{@hostname}", chain]
        end

        [nil, context.chain || chain]
      end

      def trust_anchor_verification_error(socket, certificate, chain, anchor)
        index = chain.index { |candidate| certificates_equal?(candidate, anchor) }
        return nil if index == 0
        return "matching TLSA certificate was not present in the server chain" unless index

        untrusted = index.to_i.zero? ? [] : chain[1...index]
        store = OpenSSL::X509::Store.new
        store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
        store.add_cert(anchor)

        unless store.verify(certificate, untrusted)
          return "#{store.error_string || 'unknown error'}"
        end

        nil
      end

      def certificate_store(socket)
        @cert_store || socket.context.cert_store || default_certificate_store
      end

      def default_certificate_store
        OpenSSL::X509::Store.new.tap(&:set_default_paths)
      end

      def certificates_equal?(left, right)
        left.to_der == right.to_der
      end

      def association_failure(record)
        "no certificate matched TLSA record #{record}"
      end

      def unsupported_records_message
        details = unknown_records.map do |record|
          unknown = []
          unknown << "usage #{record.usage}" unless (0..3).include?(record.usage)
          unknown << "selector #{record.selector}" unless [0, 1].include?(record.selector)
          unknown << "matching type #{record.matching_type}" unless [0, 1, 2].include?(record.matching_type)
          unknown.join(', ')
        end
        "no usable TLSA records for #{@hostname}: unknown #{details.join('; ')}"
      end
    end
  end
end
