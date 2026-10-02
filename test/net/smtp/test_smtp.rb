# coding: utf-8

require 'net/smtp'
require 'test/unit'

module Net
  class TestSMTP < Test::Unit::TestCase
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
      PipeliningServer.stop_all
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
      smtp = Net::SMTP.start 'localhost', server.port
      assert smtp.mailfrom("foo@example.com").success?
      assert_equal "MAIL FROM:<foo@example.com>\r\n", server.commands.last
      smtp.finish
    end

    def test_mailfrom_with_address
      server = FakeServer.start
      smtp = Net::SMTP.start 'localhost', server.port
      addr = Net::SMTP::Address.new("foo@example.com", size: 12345)
      assert smtp.mailfrom(addr).success?
      assert_equal "MAIL FROM:<foo@example.com> size=12345\r\n", server.commands.last
    end

    def test_rcptto
      server = FakeServer.start
      smtp = Net::SMTP.start 'localhost', server.port
      assert smtp.rcptto("foo@example.com").success?
      assert_equal "RCPT TO:<foo@example.com>\r\n", server.commands.last
    end

    def test_rcptto_with_address
      server = FakeServer.start
      smtp = Net::SMTP.start 'localhost', server.port
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
      smtp = Net::SMTP.start 'localhost', server.port
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

    def test_capable_pipelining
      server = PipeliningServer.start(pipelining: true)
      smtp = Net::SMTP.start 'localhost', server.port
      assert_equal true, smtp.capable_pipelining?
      smtp.finish

      server = PipeliningServer.start(pipelining: false)
      smtp = Net::SMTP.start 'localhost', server.port
      assert_equal false, smtp.capable_pipelining?
      smtp.finish
    end

    def test_send_message_pipelined
      server = PipeliningServer.start(pipelining: true)
      smtp = Net::SMTP.start 'localhost', server.port
      results = smtp.send_message_pipelined 'message', 'foo@example.com',
                                            'a@example.com', 'b@example.com', 'c@example.com'
      assert_equal %w[a@example.com b@example.com c@example.com], results.keys
      assert results.values.all?(&:success?)
      smtp.finish

      envelope = server.commands.grep(/\A(?:MAIL FROM:|RCPT TO:)/)
      assert_equal 4, envelope.size
      assert_equal "MAIL FROM:<foo@example.com>\r\n", envelope.first
      # the whole envelope was sent before the first reply was needed
      assert_operator server.max_in_flight, :>=, 4
      # every command sent got exactly its replies consumed (DATA has two)
      assert_equal server.commands.size + 1, server.replies.size
      assert_include server.body, "message\r\n"
    end

    def test_send_message_pipelined_mail_failure
      server = PipeliningServer.start(pipelining: true,
                                      mail_reply: "550 5.7.1 Sender rejected\r\n")
      smtp = Net::SMTP.start 'localhost', server.port
      ex = assert_raise(Net::SMTPFatalError) do
        smtp.send_message_pipelined 'message', 'foo@example.com',
                                    'a@example.com', 'b@example.com'
      end
      assert_equal '550', ex.response.status
      # the pipelined RCPT TO replies were consumed before raising,
      # so the session is still in sync and usable
      assert smtp.rset.success?
      smtp.finish

      assert_equal 3, server.commands.grep(/\A(?:MAIL FROM:|RCPT TO:)/).size
      assert_equal 0, server.commands.grep(/\ADATA/).size
      assert_equal server.commands.size, server.replies.size
    end

    def test_send_message_pipelined_partial_rcpt_rejected
      server = PipeliningServer.start(pipelining: true,
                                      rcpt_replies: {'bad@example.com' => "550 5.1.1 No such user\r\n"})
      smtp = Net::SMTP.start 'localhost', server.port
      results = smtp.send_message_pipelined 'message', 'foo@example.com',
                                            'good@example.com', 'bad@example.com'
      smtp.finish

      assert results['good@example.com'].success?
      assert_false results['bad@example.com'].success?
      assert_equal '550', results['bad@example.com'].status
      assert_include server.body, "message\r\n"
    end

    def test_send_message_pipelined_all_rcpt_rejected
      server = PipeliningServer.start(pipelining: true,
                                      rcpt_replies: Hash.new("550 5.1.1 No such user\r\n"))
      smtp = Net::SMTP.start 'localhost', server.port
      ex = assert_raise(Net::SMTPFatalError) do
        smtp.send_message_pipelined 'message', 'foo@example.com',
                                    'a@example.com', 'b@example.com'
      end
      assert_equal '550', ex.response.status
      # all replies were drained; the session is still usable
      assert smtp.rset.success?
      smtp.finish

      assert_equal 0, server.commands.grep(/\ADATA/).size
      assert_equal server.commands.size, server.replies.size
    end

    def test_send_message_pipelined_delayed_and_fragmented_replies
      server = PipeliningServer.start(pipelining: true,
                                      reply_delay: 0.05, fragment_replies: true)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.read_timeout = 5
      results = smtp.send_message_pipelined 'message', 'foo@example.com',
                                            'a@example.com', 'b@example.com'
      smtp.finish

      assert_equal %w[a@example.com b@example.com], results.keys
      assert results.values.all?(&:success?)
      assert_include server.body, "message\r\n"
    end

    def test_send_message_pipelined_without_capability
      server = PipeliningServer.start(pipelining: false,
                                      rcpt_replies: {'bad@example.com' => "550 5.1.1 No such user\r\n"})
      smtp = Net::SMTP.start 'localhost', server.port
      results = smtp.send_message_pipelined 'message', 'foo@example.com',
                                            'good@example.com', 'bad@example.com'
      smtp.finish

      # serial fallback: never more than one unanswered command in flight
      assert_equal 1, server.max_in_flight
      assert results['good@example.com'].success?
      assert_equal '550', results['bad@example.com'].status
      assert_include server.body, "message\r\n"
    end

    def test_send_message_pipelined_data_waits_for_continue
      events = []
      server = PipeliningServer.start(pipelining: true, events: events)
      smtp = Net::SMTP.start 'localhost', server.port
      msg = OneShotMessage.new(events)
      results = smtp.send_message_pipelined msg, 'foo@example.com', 'a@example.com'
      smtp.finish

      assert results['a@example.com'].success?
      # the one-shot message source was read only after the server
      # allowed the DATA phase with a 354 reply
      assert_operator events.index(:message_read), :>, events.index(:sent_354)
      assert_include server.body, "one-shot body\r\n"
    end

    def test_send_message_pipelined_connection_drop
      server = PipeliningServer.start(pipelining: true, close_on: /\AMAIL FROM:/)
      smtp = Net::SMTP.start 'localhost', server.port
      smtp.read_timeout = 5
      assert_raise(EOFError, SystemCallError, IOError) do
        smtp.send_message_pipelined 'message', 'foo@example.com', 'a@example.com'
      end
      # the connection cannot be resynchronized and is discarded:
      # finish must not send further commands nor raise
      smtp.finish
      assert_false smtp.started?
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

  # A message source that can be read only once, used to verify that
  # the message body is not consumed before the server allows DATA.
  class OneShotMessage
    def initialize(events)
      @events = events
      @used = false
    end

    def each(&block)
      raise 'one-shot message source consumed twice' if @used
      @used = true
      @events << :message_read
      return enum_for(:each) unless block
      "Subject: one-shot\r\n\r\none-shot body\r\n".each_line(&block)
    end
  end

  # A scriptable SMTP test server.  It records every command received
  # and every reply sent, tracks the maximum number of commands received
  # but not yet replied to (to detect pipelining), and can delay or
  # fragment its replies or drop the connection on a chosen command.
  class PipeliningServer
    @servers = []

    def self.start(**kw)
      server = new(**kw)
      @servers.push server
      server.start
      server
    end

    def self.stop_all
      while (s = @servers.shift)
        s.stop
      end
    end

    attr_reader :port, :commands, :replies, :body, :max_in_flight

    def initialize(pipelining: true, mail_reply: "250 2.1.0 Ok\r\n",
                   rcpt_replies: {}, reply_delay: 0, fragment_replies: false,
                   close_on: nil, settle: 0.05, events: nil)
      @pipelining = pipelining
      @mail_reply = mail_reply
      @rcpt_replies = rcpt_replies
      @reply_delay = reply_delay
      @fragment_replies = fragment_replies
      @close_on = close_on
      @settle = settle
      @events = events
      @commands = []
      @replies = []
      @body = +''
      @max_in_flight = 0
    end

    def start
      @server = TCPServer.new('localhost', 0)
      @port = @server.addr[1]
      @thread = Thread.start do
        Thread.current.abort_on_exception = true
        run
      end
      self
    end

    def stop
      @thread&.kill
      @thread&.join
      @server&.close
    end

    private

    def run
      sock = @server.accept
      sock.write "220 ready\r\n"
      @buf = +''
      loop do
        line = next_line(sock, true) or break
        batch = [line]
        # give pipelined commands a chance to arrive, then drain whatever
        # is already buffered to measure how many commands are in flight
        sleep @settle
        while (l = next_line(sock, false))
          batch << l
        end
        @max_in_flight = batch.size if batch.size > @max_in_flight
        batch.each do |cmd|
          return unless handle_command(sock, cmd)
        end
      end
    rescue Errno::ECONNRESET, Errno::ECONNABORTED, Errno::EPIPE, IOError
      nil
    ensure
      sock&.close rescue nil
    end

    def next_line(sock, block)
      until (i = @buf.index("\n"))
        begin
          @buf << (block ? sock.readpartial(4096) : sock.read_nonblock(4096))
        rescue IO::WaitReadable, EOFError
          return nil
        end
      end
      @buf.slice!(0..i)
    end

    def handle_command(sock, cmd)
      @commands << cmd
      if @close_on && cmd.match?(@close_on)
        sock.close
        return false
      end
      case cmd
      when /\AEHLO /
        reply sock, ehlo_reply
      when /\AMAIL FROM:/
        reply sock, @mail_reply
      when /\ARCPT TO:<([^>]+)>/
        reply sock, @rcpt_replies.fetch($1) { @rcpt_replies.default || "250 2.1.5 Ok\r\n" }
      when /\ADATA/
        @events&.push(:data_received)
        reply sock, "354 End data with <CR><LF>.<CR><LF>\r\n"
        @events&.push(:sent_354)
        while (l = next_line(sock, true))
          break if l.chomp == '.'
          @body << l
        end
        reply sock, "250 2.0.0 Ok: queued\r\n"
      when /\ARSET/
        reply sock, "250 2.0.0 Ok\r\n"
      when /\AQUIT/
        reply sock, "221 2.0.0 Bye\r\n"
        return false
      else
        reply sock, "502 5.5.2 Error: command not recognized\r\n"
      end
      true
    end

    def reply(sock, text)
      sleep @reply_delay if @reply_delay > 0
      if @fragment_replies
        text.each_char do |ch|
          sock.write ch
          sock.flush
        end
      else
        sock.write text
      end
      @replies << text
    end

    def ehlo_reply
      lines = ["250-servername\r\n"]
      lines << "250-PIPELINING\r\n" if @pipelining
      lines << "250 HELP\r\n"
      lines.join
    end
  end
end
