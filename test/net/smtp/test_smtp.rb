# coding: utf-8

require 'net/smtp'
require 'test/unit'

module Net
  class TestSMTP < Test::Unit::TestCase
    @scripted_servers = []

    class << self
      attr_reader :scripted_servers
    end

    def setup
      # Avoid hanging at fake_server_start's IO.select on --jit-wait CI like http://ci.rvm.jp/results/trunk-mjit-wait@phosphorus-docker/3302796
      # Unfortunately there's no way to configure read_timeout for Net::SMTP.start.
      if defined?(RubyVM::JIT) && RubyVM::JIT.enabled?
        Net::SMTP.prepend Module.new {
          def initialize(*)
            super
            @read_timeout *= 5
          end
        }
      end
    end

    def teardown
      FakeServer.stop_all
      while (server = self.class.scripted_servers.shift)
        server.stop
      end
    end

    def test_critical
      smtp = Net::SMTP.new 'localhost', 25

      assert_raise RuntimeError do
        smtp.send :critical do
          raise 'fail on purpose'
        end
      end

      assert_kind_of Net::SMTP::Response, smtp.send(:critical),
                     '[Bug #9125]'
    end

    def test_esmtp
      smtp = Net::SMTP.new 'localhost', 25
      assert smtp.esmtp
      assert smtp.esmtp?

      smtp.esmtp = 'omg'
      assert_equal 'omg', smtp.esmtp
      assert_equal 'omg', smtp.esmtp?
    end

    def test_server_capabilities
      if defined? OpenSSL
        port = fake_server_start(starttls: true, auth: 'plain')
        smtp = Net::SMTP.start('localhost', port, starttls: false)
        assert_equal({"STARTTLS"=>[], "AUTH"=>["PLAIN"]}, smtp.capabilities)
        assert_equal(true, smtp.capable?('STARTTLS'))
        assert_equal(false, smtp.capable?('DOES-NOT-EXIST'))
      else
        port = fake_server_start
        smtp = Net::SMTP.start('localhost', port, starttls: false)
        assert_equal({"AUTH"=>["PLAIN"]}, smtp.capabilities)
        assert_equal(false, smtp.capable?('STARTTLS'))
        assert_equal(false, smtp.capable?('DOES-NOT-EXIST'))
      end
      smtp.finish
    end

    def test_rset
      smtp = Net::SMTP.start 'localhost', fake_server_start
      assert smtp.rset
      smtp.finish
    end

    def test_mailfrom
      server = FakeServer.start
      smtp = Net::SMTP.start '127.0.0.1', server.port
      assert smtp.mailfrom("foo@example.com").success?
      assert_equal "MAIL FROM:<foo@example.com>\r\n", server.commands.last
      smtp.finish
    end

    def test_mailfrom_with_address
      server = FakeServer.start
      smtp = Net::SMTP.start '127.0.0.1', server.port
      addr = Net::SMTP::Address.new("foo@example.com", size: 12345)
      assert smtp.mailfrom(addr).success?
      assert_equal "MAIL FROM:<foo@example.com> size=12345\r\n", server.commands.last
    end

    def test_rcptto
      server = FakeServer.start
      smtp = Net::SMTP.start '127.0.0.1', server.port
      assert smtp.rcptto("foo@example.com").success?
      assert_equal "RCPT TO:<foo@example.com>\r\n", server.commands.last
    end

    def test_rcptto_with_address
      server = FakeServer.start
      smtp = Net::SMTP.start '127.0.0.1', server.port
      addr = Net::SMTP::Address.new("foo@example.com", nofty: :failure)
      assert smtp.rcptto(addr).success?
      assert_equal "RCPT TO:<foo@example.com> nofty=failure\r\n", server.commands.last
    end

    def test_address
      a = Net::SMTP::Address.new('foo@example.com', 'p0=123', {p1: 456}, p2: nil, p3: '789')
      assert_equal 'foo@example.com', a.address
      assert_equal ['p0=123', 'p1=456', 'p2', 'p3=789'], a.parameters
    end

    def test_auth_plain
      server = FakeServer.start(auth: 'plain')
      smtp = Net::SMTP.start '127.0.0.1', server.port
      assert smtp.authenticate("account", "password", :plain).success?
      assert_equal "AUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=\r\n", server.commands.last
    end

    def test_unsuccessful_auth_plain
      server = FakeServer.start(auth: 'plain')
      smtp = Net::SMTP.start 'localhost', server.port
      err = assert_raise(Net::SMTPAuthenticationError) { smtp.authenticate("foo", "bar", :plain) }
      assert_equal "535 5.7.8 Error: authentication failed: authentication failure\n", err.message
      assert_equal "535", err.response.status
    end

    def test_auth_login
      server = FakeServer.start(auth: 'login')
      smtp = Net::SMTP.start 'localhost', server.port
      assert smtp.authenticate("account", "password", :login).success?
    end

    def test_unsuccessful_auth_login
      server = FakeServer.start(auth: 'login')
      smtp = Net::SMTP.start 'localhost', server.port
      err = assert_raise(Net::SMTPAuthenticationError) { smtp.authenticate("foo", "bar", :login) }
      assert_equal "535 5.7.8 Error: authentication failed: authentication failure\n", err.message
      assert_equal "535", err.response.status
    end

    def test_non_continue_auth_login
      server = FakeServer.start(auth: 'login')
      def server.auth(*)
        @sock.puts "334 VXNlcm5hbWU6\r\n"
        @sock.gets
        @sock.puts "235 2.7.0 Authentication successful\r\n"
      end
      smtp = Net::SMTP.start 'localhost', server.port
      err = assert_raise(Net::SMTPUnknownError) { smtp.authenticate("account", "password", :login) }
      assert_equal "235 2.7.0 Authentication successful\n", err.message
      assert_equal "235", err.response.status
    end

    def test_auth_xoauth2
      server = FakeServer.start(auth: 'xoauth2')
      smtp = Net::SMTP.start 'localhost', server.port
      assert smtp.authenticate("account", "token", :xoauth2).success?
      assert_equal "AUTH XOAUTH2 dXNlcj1hY2NvdW50AWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n", server.commands.last
    end

    def test_unsuccessful_auth_xoauth2
      server = FakeServer.start(auth: 'xoauth2')
      smtp = Net::SMTP.start 'localhost', server.port
      err = assert_raise(Net::SMTPAuthenticationError) { smtp.authenticate("account", "password", :xoauth2) }
      assert_equal "535 5.7.8 Error: authentication failed: authentication failure\n", err.message
      assert_equal "535", err.response.status
    end

    def test_send_message
      port = fake_server_start
      smtp = Net::SMTP.start 'localhost', port
      assert_nothing_raised do
        smtp.send_message("message", "sender@example.com", "rcpt1@example.com")
      end
    end

    def test_send_message_with_multiple_recipients
      port = fake_server_start
      smtp = Net::SMTP.start 'localhost', port
      assert_nothing_raised do
        smtp.send_message("message", "sender@example.com", "rcpt1@example.com", "rcpt2@example.com")
      end
    end

    def test_send_message_with_multiple_recipients_as_array
      port = fake_server_start
      smtp = Net::SMTP.start 'localhost', port
      assert_nothing_raised do
        smtp.send_message("message", "sender@example.com", ["rcpt1@example.com", "rcpt2@example.com"])
      end
    end

    def test_pipelined_send_message_with_one_failed_recipient
      scripted = start_scripted_pipelined_server(:one_recipient_failed)
      result = scripted.smtp.send_message(
        'message', 'sender@example.com',
        'good1@example.com', 'bad@example.com', 'good2@example.com',
        pipelining: true
      )

      assert_equal [
        "MAIL FROM:<sender@example.com>",
        "RCPT TO:<good1@example.com>",
        "RCPT TO:<bad@example.com>",
        "RCPT TO:<good2@example.com>",
        "DATA"
      ], scripted.envelope_commands
      assert_equal '250', result[:mail].status
      assert_equal %w[good1@example.com bad@example.com good2@example.com],
                   result[:recipients].map { |item| item[:address] }
      assert_equal %w[250 550 250],
                   result[:recipients].map { |item| item[:response].status }
      assert_equal '354', result[:data].status
      assert result[:message].success?
      assert_equal "message\r\n", scripted.body
      assert_not_include scripted.commands, "RSET\r\n"
    end

    def test_pipelined_send_message_with_multiline_response
      scripted = start_scripted_pipelined_server(:multiline_recipient)
      result = scripted.smtp.send_message(
        'message', 'sender@example.com',
        'rcpt1@example.com', 'rcpt2@example.com', 'rcpt3@example.com',
        pipelining: true
      )

      assert_equal %w[250 250 250], result[:recipients].map { |item| item[:response].status }
      assert_equal "250-first line\n250 second line\n", result[:recipients][1][:response].string
      assert result[:message].success?
    end

    def test_pipelined_send_message_with_all_recipients_failed
      scripted = start_scripted_pipelined_server(:all_recipients_failed)
      error = assert_raise(Net::SMTPFatalError) do
        scripted.smtp.send_message(
          'message', 'sender@example.com',
          'bad1@example.com', 'bad2@example.com', 'bad3@example.com',
          pipelining: true
        )
      end

      assert_equal '550', error.response.status
      assert_equal %w[550 450 553],
                   error.envelope[:recipients].map { |item| item[:response].status }
      assert_equal '451', error.envelope[:data].status
      assert_equal '', scripted.body
      assert_include scripted.commands, "RSET\r\n"
      assert_equal '250', error.envelope[:mail].status

      assert scripted.smtp.rset.success?
      assert scripted.smtp.send_message('second message', 'sender@example.com', 'good@example.com').success?
    end

    def test_pipelined_data_rejected
      scripted = start_scripted_pipelined_server(:data_rejected)
      error = assert_raise(Net::SMTPUnknownError) do
        scripted.smtp.send_message(
          'message', 'sender@example.com',
          'rcpt1@example.com', 'rcpt2@example.com', 'rcpt3@example.com',
          pipelining: true
        )
      end

      assert_equal '451', error.response.status
      assert result = error.envelope
      assert result[:mail].success?
      assert result[:recipients].all? { |item| item[:response].success? }
      assert_equal '', scripted.body
      assert_include scripted.commands, "RSET\r\n"
      assert scripted.smtp.rset.success?
    end

    def test_pipelined_mail_failed_uses_rset_after_draining_replies
      scripted = start_scripted_pipelined_server(:mail_failed_rset)
      error = assert_raise(Net::SMTPFatalError) do
        scripted.smtp.send_message(
          'message', 'sender@example.com',
          'rcpt1@example.com', 'rcpt2@example.com', 'rcpt3@example.com',
          pipelining: true
        )
      end

      assert_equal '550', error.response.status
      assert_equal %w[553 450 553],
                   error.envelope[:recipients].map { |item| item[:response].status }
      assert_equal '451', error.envelope[:data].status
      assert_include scripted.commands, "RSET\r\n"
      assert scripted.smtp.rset.success?
    end

    def test_pipelined_mail_failed_and_connection_closed
      scripted = start_scripted_pipelined_server(:mail_failed_closed)
      assert_raise(EOFError) do
        scripted.smtp.send_message(
          'message', 'sender@example.com',
          'rcpt1@example.com', 'rcpt2@example.com', 'rcpt3@example.com',
          pipelining: true
        )
      end

      scripted.join
      assert_equal [
        "MAIL FROM:<sender@example.com>",
        "RCPT TO:<rcpt1@example.com>",
        "RCPT TO:<rcpt2@example.com>",
        "RCPT TO:<rcpt3@example.com>",
        "DATA"
      ], scripted.envelope_commands
      assert_not_include scripted.commands, "RSET\r\n"
    end

    def test_pipelined_data_421_closes_without_rset
      scripted = start_scripted_pipelined_server(:data_421)
      error = assert_raise(Net::SMTPUnknownError) do
        scripted.smtp.send_message(
          'message', 'sender@example.com',
          'rcpt1@example.com', 'rcpt2@example.com', 'rcpt3@example.com',
          pipelining: true
        )
      end

      assert_equal '421', error.response.status
      assert_not_include scripted.commands, "RSET\r\n"
    end

    def test_pipelining_falls_back_without_capability
      events = []
      socket = Object.new
      io = Object.new
      socket.define_singleton_method(:io) { io }
      responses = [
        Net::SMTP::Response.parse("250 sender ok\n"),
        Net::SMTP::Response.parse("250 recipient ok\n"),
        Net::SMTP::Response.parse("354 continue\n"),
        Net::SMTP::Response.parse("250 queued\n")
      ]
      io.define_singleton_method(:sync) { true }
      io.define_singleton_method(:sync=) { |value| events << [:sync, value] }
      io.define_singleton_method(:flush) { events << :flush }
      socket.define_singleton_method(:writeline) { |line| events << [:write, line] }
      socket.define_singleton_method(:write) { |data| events << [:batch, data] }
      socket.define_singleton_method(:write_message) { |message| events << [:body, message] }
      socket.define_singleton_method(:readline) { nil }
      socket.define_singleton_method(:closed?) { false }

      smtp = Net::SMTP.new('localhost')
      smtp.instance_variable_set(:@socket, socket)
      smtp.instance_variable_set(:@capabilities, {})
      reads = 0
      smtp.define_singleton_method(:recv_response) do
        response = responses[reads]
        reads += 1
        events << [:read, response.status]
        response
      end

      result = smtp.send_message('message', 'sender@example.com', 'rcpt@example.com',
                                 pipelining: true)

      assert_equal '250', result.status
      assert_equal [
        [:write, 'MAIL FROM:<sender@example.com>'],
        [:read, '250'],
        [:write, 'RCPT TO:<rcpt@example.com>'],
        [:read, '250'],
        [:write, 'DATA'],
        [:read, '354'],
        [:sync, false],
        [:body, 'message'],
        :flush,
        [:sync, true],
        [:read, '250']
      ], events
    end

    def test_pipelined_instance_option
      scripted = start_scripted_pipelined_server(:one_recipient_failed)
      scripted.smtp.pipelining = true
      result = scripted.smtp.send_message(
        'message', 'sender@example.com',
        'good1@example.com', 'bad@example.com', 'good2@example.com'
      )

      assert_equal '354', result[:data].status
      assert_equal %w[250 550 250],
                   result[:recipient_responses].map(&:status)
    end

    def test_unsuccessful_send_message_server_busy
      server = FakeServer.new
      def server.greeting
        @sock.puts "400 BUSY\r\n"
      end
      server.start
      err = assert_raise(Net::SMTPServerBusy) { Net::SMTP.start 'localhost', server.port }
      assert_equal "400 BUSY\n", err.message
      assert_equal "400", err.response.status
    end

    def test_unsuccessful_send_message_syntax_error
      server = FakeServer.new
      def server.greeting
        @sock.puts "502 SYNTAX ERROR\r\n"
      end
      server.start
      err = assert_raise(Net::SMTPSyntaxError) { Net::SMTP.start 'localhost', server.port }
      assert_equal "502 SYNTAX ERROR\n", err.message
      assert_equal "502", err.response.status
    end

    def test_unsuccessful_send_message_authentication_error
      server = FakeServer.new
      def server.greeting
        @sock.puts "530 AUTH ERROR\r\n"
      end
      server.start
      err = assert_raise(Net::SMTPAuthenticationError) { Net::SMTP.start 'localhost', server.port }
      assert_equal "530 AUTH ERROR\n", err.message
      assert_equal "530", err.response.status
    end

    def test_unsuccessful_send_message_fatal_error
      server = FakeServer.new
      def server.greeting
        @sock.puts "520 FATAL ERROR\r\n"
      end
      server.start
      err = assert_raise(Net::SMTPFatalError) { Net::SMTP.start 'localhost', server.port }
      assert_equal "520 FATAL ERROR\n", err.message
      assert_equal "520", err.response.status
    end

    def test_unsuccessful_send_message_unknown_error
      server = FakeServer.new
      def server.greeting
        @sock.puts "300 UNKNOWN\r\n"
      end
      server.start
      err = assert_raise(Net::SMTPUnknownError) { Net::SMTP.start 'localhost', server.port }
      assert_equal "300 UNKNOWN\n", err.message
      assert_equal "300", err.response.status
    end

    def test_unsuccessful_data
      server = FakeServer.new
      def server.data
        @sock.puts "250 OK\r\n"
      end
      server.start
      smtp = Net::SMTP.start 'localhost', server.port
      err = assert_raise(Net::SMTPUnknownError) { smtp.data('message') }
      assert_equal "could not get 3xx (250: 250 OK\n)", err.message
      assert_equal "250", err.response.status
    end

    def test_crlf_injection
      server = FakeServer.new
      smtp = Net::SMTP.new 'localhost', server.port

      assert_raise(ArgumentError) do
        smtp.mailfrom("foo\r\nbar")
      end

      assert_raise(ArgumentError) do
        smtp.mailfrom("foo\rbar")
      end

      assert_raise(ArgumentError) do
        smtp.mailfrom("foo\nbar")
      end

      assert_raise(ArgumentError) do
        smtp.rcptto("foo\r\nbar")
      end
    end

    def test_tls_connect
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(tls: true)
      smtp = Net::SMTP.new("localhost", server.port, tls_verify: false)
      smtp.enable_tls
      smtp.open_timeout = 1
      smtp.start{}
    ensure
      server.stop
    end

    def test_tls_connect_timeout
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.new
      def server.init
        sleep
      end
      server.start(tls: true)
      smtp = Net::SMTP.new("localhost", server.port)
      smtp.enable_tls
      smtp.open_timeout = 0.1
      assert_raise(Net::OpenTimeout) do
        smtp.start{}
      end
    ensure
      server.stop
    end

    def test_eof_error_backtrace
      bug13018 = '[ruby-core:78550] [Bug #13018]'

      server = FakeServer.new
      def server.ehlo(*)
        @sock.shutdown(:WR)
      end

      begin
        server.start
        smtp = Net::SMTP.new("localhost", server.port)
        e = assert_raise(EOFError, bug13018) do
          smtp.start{}
        end
        assert_equal(EOFError, e.class, bug13018)
        assert(e.backtrace.grep(%r"\bnet/smtp\.rb:").size > 0, bug13018)
      ensure
        server.stop
      end
    end

    def test_with_tls
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(tls: true)
      smtp = Net::SMTP.new('localhost', server.port, tls: true, tls_verify: false)
      assert_nothing_raised do
        smtp.start{}
      end

      server = FakeServer.start(tls: false)
      smtp = Net::SMTP.new('localhost', server.port, tls: false)
      assert_nothing_raised do
        smtp.start{}
      end
    end

    def test_with_starttls_always
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(starttls: true)
      smtp = Net::SMTP.new('localhost', server.port, starttls: :always, tls_verify: false)
      smtp.start{}
      assert_equal(true, server.starttls_started?)

      server = FakeServer.start(starttls: false)
      smtp = Net::SMTP.new('localhost', server.port, starttls: :always, tls_verify: false)
      assert_raise Net::SMTPUnsupportedCommand do
        smtp.start{}
      end
    end

    def test_with_starttls_auto
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(starttls: true)
      smtp = Net::SMTP.new('localhost', server.port, starttls: :auto, tls_verify: false)
      smtp.start{}
      assert_equal(true, server.starttls_started?)

      server = FakeServer.start(starttls: false)
      smtp = Net::SMTP.new('localhost', server.port, starttls: :auto, tls_verify: false)
      smtp.start{}
      assert_equal(false, server.starttls_started?)
    end

    def test_with_starttls_false
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(starttls: true)
      smtp = Net::SMTP.new('localhost', server.port, starttls: false, tls_verify: false)
      smtp.start{}
      assert_equal(false, server.starttls_started?)

      server = FakeServer.start(starttls: false)
      smtp = Net::SMTP.new('localhost', server.port, starttls: false, tls_verify: false)
      smtp.start{}
      assert_equal(false, server.starttls_started?)
    end

    def test_start
      port = fake_server_start
      smtp = Net::SMTP.start('localhost', port)
      smtp.finish
    end

    def test_start_with_position_argument
      port = fake_server_start(auth: 'plain')
      smtp = Net::SMTP.start('localhost', port, 'myname', 'account', 'password', :plain)
      smtp.finish
    end

    def test_start_with_keyword_argument
      port = fake_server_start(auth: 'plain')
      smtp = Net::SMTP.start('localhost', port, helo: 'myname', user: 'account', secret: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_password_is_secret
      port = fake_server_start(auth: 'plain')
      smtp = Net::SMTP.start('localhost', port, helo: 'myname', user: 'account', password: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_invalid_number_of_arguments
      err = assert_raise ArgumentError do
        Net::SMTP.start('localhost', 25, 'myname', 'account', 'password', :plain, :invalid_arg)
      end
      assert_equal('wrong number of arguments (given 7, expected 1..6)', err.message)
    end

    def test_start_with_tls
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(tls: true)
      assert_nothing_raised do
        Net::SMTP.start('localhost', port, tls: true, tls_verify: false){}
      end

      port = fake_server_start(tls: false)
      assert_nothing_raised do
        Net::SMTP.start('localhost', port, tls: false){}
      end
    end

    def test_start_with_starttls_always
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(starttls: true)
      Net::SMTP.start('localhost', server.port, starttls: :always, tls_verify: false){}
      assert_equal(true, server.starttls_started?)

      server = FakeServer.start(starttls: false)
      assert_raise Net::SMTPUnsupportedCommand do
        Net::SMTP.start('localhost', server.port, starttls: :always, tls_verify: false){}
      end
    end

    def test_start_with_starttls_auto
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(starttls: true)
      Net::SMTP.start('localhost', server.port, starttls: :auto, tls_verify: false){}
      assert_equal(true, server.starttls_started?)

      server = FakeServer.start(starttls: false)
      Net::SMTP.start('localhost', server.port, starttls: :auto, tls_verify: false){}
      assert_equal(false, server.starttls_started?)
    end

    def test_start_with_starttls_false
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      server = FakeServer.start(starttls: true)
      Net::SMTP.start('localhost', server.port, starttls: false, tls_verify: false){}
      assert_equal(false, server.starttls_started?)

      server = FakeServer.start(starttls: false)
      Net::SMTP.start('localhost', server.port, starttls: false, tls_verify: false){}
      assert_equal(false, server.starttls_started?)
    end

    def test_start_auth_plain
      port = fake_server_start(auth: 'plain')
      Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :plain){}

      port = fake_server_start(auth: 'plain')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'invalid', authtype: :plain){}
      end

      port = fake_server_start(auth: 'login')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :plain){}
      end
    end

    def test_start_auth_login
      port = fake_server_start(auth: 'LOGIN')
      Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :login){}

      port = fake_server_start(auth: 'LOGIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'invalid', authtype: :login){}
      end

      port = fake_server_start(auth: 'PLAIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :login){}
      end
    end

    def test_start_auth_cram_md5
      omit "openssl or digest library not loaded" unless defined? OpenSSL or defined? Digest

      port = fake_server_start(auth: 'CRAM-MD5')
      Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: "CRAM-MD5"){}

      port = fake_server_start(auth: 'CRAM-MD5')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'invalid', authtype: :cram_md5){}
      end

      port = fake_server_start(auth: 'PLAIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :cram_md5){}
      end

      port = fake_server_start(auth: 'CRAM-MD5')
      smtp = Net::SMTP.new('localhost', port)
      auth_cram_md5 = Net::SMTP::AuthCramMD5.new(smtp)
      auth_cram_md5.define_singleton_method(:digest_class) { raise '"openssl" or "digest" library is required' }
      Net::SMTP::AuthCramMD5.define_singleton_method(:new) { |_| auth_cram_md5 }
      e = assert_raise RuntimeError do
        smtp.start(user: 'account', password: 'password', authtype: :cram_md5){}
      end
      assert_equal('"openssl" or "digest" library is required', e.message)
    end

    def test_start_instance
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start
      smtp.finish
    end

    def test_start_instance_after_failed_greeting
      smtp = Net::SMTP.new("example.invalid", starttls: false)
      socket = Object.new
      socket.define_singleton_method(:close) {}
      smtp.define_singleton_method(:tcp_socket) { |*| socket }
      smtp.define_singleton_method(:new_internet_message_io) { |io| io }
      greetings = 0
      smtp.define_singleton_method(:recv_response) do
        greetings += 1
        raise EOFError if greetings == 1
        Net::SMTP::Response.parse("220 ready")
      end
      smtp.define_singleton_method(:do_helo) { |_| }
      smtp.define_singleton_method(:do_finish) do
        @started = false
        @socket = nil
      end

      assert_raise(EOFError) { smtp.start }
      smtp.start
      assert_equal 2, greetings
      assert smtp.started?
    ensure
      smtp.finish if smtp&.started?
    end

    def test_start_instance_with_position_argument
      port = fake_server_start(auth: 'plain')
      smtp = Net::SMTP.new('localhost', port)
      smtp.start('myname', 'account', 'password', :plain)
      smtp.finish
    end

    def test_start_instance_with_keyword_argument
      port = fake_server_start(auth: 'plain')
      smtp = Net::SMTP.new('localhost', port)
      smtp.start(helo: 'myname', user: 'account', secret: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_instance_password_is_secret
      port = fake_server_start(auth: 'plain')
      smtp = Net::SMTP.new('localhost', port)
      smtp.start(helo: 'myname', user: 'account', password: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_instance_invalid_number_of_arguments
      smtp = Net::SMTP.new('localhost')
      err = assert_raise ArgumentError do
        smtp.start('myname', 'account', 'password', :plain, :invalid_arg)
      end
      assert_equal('wrong number of arguments (given 5, expected 0..4)', err.message)
    end

    def test_send_smtputf_sender_without_server
      server = FakeServer.start(smtputf8: false)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.send_message('message', 'rené@example.com', 'foo@example.com')
      assert server.commands.include? "MAIL FROM:<rené@example.com>\r\n"
    end

    def test_send_smtputf8_sender
      server = FakeServer.start(smtputf8: true)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.send_message('message', 'rené@example.com', 'foo@example.com')
      assert server.commands.include? "MAIL FROM:<rené@example.com> SMTPUTF8\r\n"
    end

    def test_send_smtputf8_sender_with_size
      server = FakeServer.start(smtputf8: true)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.send_message('message', Net::SMTP::Address.new('rené@example.com', 'SIZE=42'), 'foo@example.com')
      assert server.commands.include? "MAIL FROM:<rené@example.com> SIZE=42 SMTPUTF8\r\n"
    end

    def test_send_smtputf_recipient
      server = FakeServer.start(smtputf8: true)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.send_message('message', 'foo@example.com', 'rené@example.com')
      assert server.commands.include? "MAIL FROM:<foo@example.com> SMTPUTF8\r\n"
    end

    def test_mailfrom_with_smtputf_detection
      server = FakeServer.start(smtputf8: true)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.mailfrom("rené@example.com")
      assert_equal "MAIL FROM:<rené@example.com> SMTPUTF8\r\n", server.commands.last
    end

    def fake_server_start(**kw)
      server = FakeServer.new
      server.start(**kw)
      server.port
    end

    def start_scripted_pipelined_server(scenario)
      server = ScriptedPipelinedServer.start(scenario)
      self.class.scripted_servers.push(server)
      server
    end
  end

  class FakeServer
    CA_FILE = File.expand_path("../fixtures/cacert.pem", __dir__)
    SERVER_KEY = File.expand_path("../fixtures/server.key", __dir__)
    SERVER_CERT = File.expand_path("../fixtures/server.crt", __dir__)

    @servers = []

    def self.start(**kw)
      server = self.new
      @servers.push server
      server.start(**kw)
      server
    end

    def self.stop_all
      while (s = @servers.shift)
        s.stop
      end
    end

    attr_reader :port
    attr_reader :commands
    attr_reader :body

    def starttls_started?
      !!@starttls_started
    end

    def start(**capabilities)
      @commands = []
      @body = +''
      @capa = capabilities
      @tls = @capa.delete(:tls)
      @servers = Socket.tcp_server_sockets('localhost', 0)
      @port = @servers[0].local_address.ip_port
      @server_thread = Thread.start do
        Thread.current.abort_on_exception = true
        init
        loop
      end
    end

    def stop
      @server_thread&.kill
      @server_thread&.join
      @servers&.each(&:close)
    end

    def init
      @sock = Socket.accept_loop(@servers) { |s, _| break s }
      if @tls
        @sock = ssl_socket
        @sock.sync_close = true
        @sock.accept
      end
      greeting
    end

    def ssl_socket
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ca_file = CA_FILE
      ctx.key = File.open(SERVER_KEY){|f| OpenSSL::PKey::RSA.new(f)}
      ctx.cert = File.open(SERVER_CERT){|f| OpenSSL::X509::Certificate.new(f)}
      OpenSSL::SSL::SSLSocket.new(@sock, ctx)
    end

    def greeting
      @sock.puts "220 ready\r\n"
    end

    def ehlo(_)
      res = [+"220-servername\r\n"]
      @capa.each do |k, v|
        case v
        when nil, false
          # do nothing
        when true
          res.push "220-#{k.upcase}\r\n"
        when String
          res.push "220-#{k.upcase} #{v.upcase}\r\n"
        when Array
          res.push "220-#{k.upcase} #{v.map(&:upcase).join(' ')}\r\n"
        else
          raise "invalid capacities: #{k}=>#{v}"
        end
      end
      res.last.sub!(/^220-/, '220 ')
      @sock.puts res.join
    end

    def starttls
      unless @capa[:starttls]
        @sock.puts "502 5.5.1 Error: command not implemented\r\n"
        return
      end
      @sock.puts "220 2.0.0 Ready to start TLS\r\n"
      @sock = ssl_socket
      @sock.sync_close = true
      @sock.accept
      @starttls_started = true
    end

    def auth(*args)
      unless @capa[:auth]
        @sock.puts "503 5.5.1 Error: authentication not enabled\r\n"
        return
      end
      type, arg = args
      unless Array(@capa[:auth]).map(&:upcase).include? type.upcase
        @sock.puts "535 5.7.8 Error: authentication failed: no mechanism available\r\n"
        return
      end
      # The account and password are fixed to "account" and "password".
      result = case type
               when 'PLAIN'
                 arg == 'AGFjY291bnQAcGFzc3dvcmQ='
               when 'LOGIN'
                 @sock.puts "334 VXNlcm5hbWU6\r\n"
                 u = @sock.gets.unpack1('m')
                 @sock.puts "334 UGFzc3dvcmQ6\r\n"
                 p = @sock.gets.unpack1('m')
                 u == 'account' && p == 'password'
               when 'CRAM-MD5'
                 @sock.puts "334 PDEyMzQ1Njc4OTAuMTIzNDVAc2VydmVybmFtZT4=\r\n"
                 r = @sock.gets&.chomp
                 r == 'YWNjb3VudCAyYzBjMTgxZjkxOGU2ZGM5Mjg3Zjk3N2E1ODhiMzg1YQ=='
               when 'XOAUTH2'
                 arg == 'dXNlcj1hY2NvdW50AWF1dGg9QmVhcmVyIHRva2VuAQE='
               end
      if result
        @sock.puts "235 2.7.0 Authentication successful\r\n"
      else
        @sock.puts "535 5.7.8 Error: authentication failed: authentication failure\r\n"
      end
    end

    def mail(_)
      @sock.puts "250 2.1.0 Ok\r\n"
    end

    def rcpt(_)
      @sock.puts "250 2.1.0 Ok\r\n"
    end

    def data
      @sock.puts "354 End data with <CR><LF>.<CR><LF>\r\n"
      while (l = @sock.gets)
        break if l.chomp == '.'
        @body.concat l.sub(/^\./, '')
      end
      @sock.puts "250 2.0.0 Ok: queued as ABCDEFG\r\n"
    end

    def rset
      @sock.puts "250 2.0.0 Ok\r\n"
    end

    def quit
      @sock.puts "221 2.0.0 Bye\r\n"
      @sock.close
      @servers.each(&:close)
    end

    def loop
      while (comm = @sock.gets)
        @commands.push comm.encode('utf-8', 'utf-8')
        case comm.chomp
        when /\AEHLO /
          ehlo(comm.split[1])
        when "STARTTLS"
          starttls
        when /\AAUTH /
          auth(*$'.split)
        when /\AMAIL FROM:/
          mail($')
        when /\ARCPT TO:/
          rcpt($')
        when "DATA"
          data
        when "RSET"
          rset
        when "QUIT"
          quit
          break
        else
          @sock.puts "502 5.5.2 Error: command not recognized\r\n"
        end
      end
    rescue Errno::ECONNRESET, Errno::ECONNABORTED
      nil
    end
  end

  class ScriptedPipelinedServer
    attr_reader :commands, :body, :envelope_commands, :smtp

    def self.start(scenario)
      new(scenario).start
    end

    def initialize(scenario)
      @scenario = scenario
      @commands = []
      @body = +''
      @pipelined_envelope_pending = true
    end

    def start
      client_read, server_write = IO.pipe
      server_read, client_write = IO.pipe
      smtp = Net::SMTP.new('localhost')
      smtp.instance_variable_set(:@socket,
                                Net::InternetMessageIO.new(DuplexIO.new(client_read, client_write),
                                                           read_timeout: 5))
      smtp.instance_variable_set(:@capabilities, { 'PIPELINING' => [] })
      smtp.instance_variable_set(:@started, true)

      server_write.write("220 ready\r\n")
      smtp.send(:recv_response)
      @smtp = smtp
      @client_read = client_read
      @client_write = client_write
      @server_read = server_read
      @server_write = server_write
      @thread = Thread.start do
        serve(server_read, server_write)
      end
      self
    end

    def join
      @thread.join
    end

    def stop
      @thread.kill
      @thread.join
      @server_read.close rescue nil
      @server_write.close rescue nil
      @client_read&.close rescue nil
      @client_write&.close rescue nil
    end

    def serve(input, output)
      loop do
        command = input.gets
        break unless command
        @commands << command

        case command.chomp
        when /\AEHLO /
          output.write("250-servername\r\n250-PIPELINING\r\n250 OK\r\n")
        when /\AMAIL FROM:/
          if @pipelined_envelope_pending
            envelope = [command] + 4.times.map { input.gets }
            envelope.each { |line| @commands << line }
            @envelope_commands = envelope.map { |line| line.chomp("\r\n") }
            respond_to_envelope(input, output)
          else
            output.write("250 sender ok\r\n")
          end
        when "RSET"
          @pipelined_envelope_pending = false
          output.write("250 reset\r\n")
        when /\ARCPT TO:/
          output.write("250 recipient ok\r\n")
        when "DATA"
          output.write("354 continue\r\n")
          read_body(input)
          output.write("250 queued\r\n")
        when "QUIT"
          output.write("221 bye\r\n")
          break
        end
      end
    rescue IOError, Errno::EPIPE
      nil
    ensure
      output.close rescue nil
    end

    def respond_to_envelope(input, output)
      case @scenario
      when :one_recipient_failed
        output.write("250 sender ok\r\n")
        output.write("250 recipient ok\r\n")
        output.write("550 recipient rejected\r\n")
        output.write("250 recipient ok\r\n")
        output.write("354 send content\r\n")
        read_body(input)
        output.write("250 queued\r\n")
      when :multiline_recipient
        output.write("250 sender ok\r\n")
        output.write("250 recipient ok\r\n")
        output.write("250-first line\r\n250 second line\r\n")
        output.write("250 recipient ok\r\n")
        output.write("354 send content\r\n")
        read_body(input)
        output.write("250 queued\r\n")
      when :all_recipients_failed
        output.write("250 sender ok\r\n550 mailbox unavailable\r\n450 try again\r\n553 invalid\r\n451 no valid recipients\r\n")
      when :data_rejected
        output.write("250 sender ok\r\n250 recipient ok\r\n250 recipient ok\r\n250 recipient ok\r\n451 data rejected\r\n")
      when :data_421
        output.write("250 sender ok\r\n250 recipient ok\r\n250 recipient ok\r\n250 recipient ok\r\n421 shutting down\r\n")
      when :mail_failed_rset
        output.write("550 sender rejected\r\n553 relay denied\r\n450 mailbox busy\r\n553 relay denied\r\n451 aborted\r\n")
      when :mail_failed_closed
        output.write("550 sender rejected\r\n553 relay denied\r\n450 mailbox busy\r\n")
        output.flush
        output.close
        input.close
      end
    end

    def read_body(input)
      while (line = input.gets)
        break if line.chomp == '.'
        @body << line.sub(/^\./, '')
      end
    end

    class DuplexIO
      attr_accessor :sync

      def initialize(read_io, write_io)
        @read_io = read_io
        @write_io = write_io
        @sync = true
      end

      def to_io
        @read_io
      end

      def readline
        @read_io.readline
      end

      def read_nonblock(maxlen, outbuf = nil, exception: true)
        @read_io.read_nonblock(maxlen, outbuf, exception: exception)
      end

      def write(data)
        @write_io.write(data)
      end

      def write_nonblock(data, exception: true)
        @write_io.write_nonblock(data, exception: exception)
      end

      def flush
        @write_io.flush
      end

      def close
        @read_io.close rescue nil
        @write_io.close rescue nil
      end
    end
  end
end
