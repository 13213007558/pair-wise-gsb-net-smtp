# frozen_string_literal: true

require 'net/smtp'
require 'delegate'
require 'socket'
require 'test/unit'

module Net
  class TestSMTPPipelining < Test::Unit::TestCase
    def teardown
      @server&.stop
      @smtp&.finish if @smtp&.started?
    end

    def test_pipelines_envelope_and_preserves_recipient_results
      start_server(rcpt: {
        'good1@example.com' => '250 2.1.5 OK',
        'bad@example.com' => "550-5.7.1 No relay\n550 5.7.1 Denied",
        'good2@example.com' => '250 2.1.5 OK'
      })
      result = send_mail(pipelining: true)

      assert_equal [mail_command, *rcpt_commands, 'DATA'], @server.envelope_commands
      assert_equal %w[250 250 550 250 354], statuses([
        result.mail_response,
        *result.recipients.map(&:response),
        result.data_response
      ])
      assert_equal 'message', @server.body
      assert_equal ['good1@example.com', 'good2@example.com'], result.accepted_recipients.map(&:address)
      assert_equal ['bad@example.com'], result.rejected_recipients.map(&:address)
      assert_equal '550', result['bad@example.com'].status
    end

    def test_envelope_commands_are_buffered_together
      start_server
      send_mail(pipelining: true)

      assert_equal 1, @envelope_writes.length
      assert_equal [
        "#{mail_command}\r\n",
        *rcpt_commands.map { |command| "#{command}\r\n" },
        "DATA\r\n"
      ], @envelope_writes.first
    end

    def test_all_recipients_rejected_resets_and_leaves_no_queued_responses
      start_server(rcpt: all_recipients('550 5.7.1 Denied'),
                   data: '450 4.7.1 No valid recipients')

      error = assert_raise(Net::SMTPFatalError) { send_mail(pipelining: true) }
      assert_equal '550', error.response.status
      assert_equal %w[550 550 550], error.envelope_response.recipients.map(&:status)
      assert_equal [mail_command, *rcpt_commands, 'DATA', 'RSET'], command_names
      assert_equal '250', @smtp.rset.status
    end

    def test_mail_rejected_consumes_all_pipelined_responses
      start_server(mail: '550 5.7.1 Sender denied',
                   rcpt: all_recipients('250 2.1.5 OK'),
                   data: '503 5.5.1 Bad sequence')

      error = assert_raise(Net::SMTPFatalError) { send_mail(pipelining: true) }
      assert_equal '550', error.response.status
      assert_equal %w[250 250 250], error.envelope_response.recipients.map(&:status)
      assert_equal [mail_command, *rcpt_commands, 'DATA', 'RSET'], command_names
      assert_empty @server.body
      assert_equal '250', @smtp.rset.status
    end

    def test_data_rejected_resets_before_next_message
      start_server(data: '503 5.5.1 Bad sequence')

      error = assert_raise(Net::SMTPUnknownError) { send_mail(pipelining: true) }
      assert_equal '503', error.response.status
      assert_equal [mail_command, *rcpt_commands, 'DATA', 'RSET'], command_names

      @server.data_response = '354 ready'
      assert_nothing_raised { send_mail(pipelining: true) }
    end

    def test_body_final_response_rejected_closes_without_leaving_responses
      start_server(final: '451 4.3.0 Try again')

      assert_raise(Net::SMTPServerBusy) { send_mail(pipelining: true) }
      assert_equal 'message', @server.body
      assert_nil @smtp.instance_variable_get(:@socket)
      assert @smtp.instance_variable_get(:@error_occurred)
    end

    def test_connection_closed_mid_envelope_does_not_leave_responses
      start_server(close_after: 2)

      assert_raise(EOFError) { send_mail(pipelining: true) }
      assert_nil @smtp.instance_variable_get(:@socket)
    end

    def test_without_server_capability_falls_back_to_sequential_commands
      start_server(pipelining: false)

      result = send_mail(pipelining: true)
      assert_equal [mail_command, *rcpt_commands, 'DATA'], @server.envelope_commands
      assert_equal Net::SMTP::Response, result.class
    end

    private

    def recipients
      %w[good1@example.com bad@example.com good2@example.com]
    end

    def mail_command
      'MAIL FROM:<sender@example.com>'
    end

    def rcpt_commands
      recipients.map { |address| "RCPT TO:<#{address}>" }
    end

    def all_recipients(status)
      recipients.each_with_object({}) { |address, responses| responses[address] = status }
    end

    def start_server(pipelining: true, **options)
      @pipelining_capability = pipelining
      @server = ScriptedPipeliningServer.new(**options)
      @server.start(pipelining: pipelining)
      @smtp = Net::SMTP.new('localhost', 0, starttls: false)
      @smtp.read_timeout = 5
      server = @server
      @envelope_writes = []
      envelope_writes = @envelope_writes
      @smtp.define_singleton_method(:tcp_socket) { |*, **| server.client_io }
      @smtp.define_singleton_method(:new_internet_message_io) do |io|
        RecordingIO.new(super(io), envelope_writes)
      end
      @smtp.start
    end

    def send_mail(**options)
      @smtp.send_message('message', 'sender@example.com', recipients, **options)
    end

    def statuses(responses)
      responses.map(&:status)
    end

    def command_names
      @server.commands.map { |command| command.chomp("\r\n") }.drop(1)
    end
  end

  class RecordingIO < SimpleDelegator
    def initialize(io, writes)
      super(io)
      @writes = writes
    end

    def write(*args)
      @writes << args.map(&:dup) if args.any? { |arg| arg.start_with?('MAIL FROM:') }
      super
    end
  end

  class ScriptedPipeliningServer
    attr_accessor :data_response
    attr_reader :client_io, :commands, :envelope_commands, :body

    def initialize(mail: '250 2.1.0 OK', rcpt: {}, data: '354 ready', final: '250 2.0.0 queued', close_after: nil)
      @mail_response = mail
      @rcpt_responses = rcpt
      @data_response = data
      @final_response = final
      @close_after = close_after
      @commands = []
      @envelope_commands = []
      @body = +''
    end

    def start(pipelining: true)
      @client_io, @server_io = Socket.pair(:UNIX, :STREAM)
      @pipelining = pipelining
      @thread = Thread.start do
        Thread.current.abort_on_exception = true
        run
      end
    end

    def stop
      @thread&.kill
      @thread&.join
      [@client_io, @server_io].each(&:close) unless @client_io&.closed?
    end

    private

    def run
      @server_io.puts "220 ready\r\n"
      pending = []
      while (line = @server_io.gets)
        command = line.chomp
        @commands << "#{command}\r\n"

        case command
        when /\AEHLO /
          greet
        when /\AMAIL FROM:/, /\ARCPT TO:/, 'DATA'
          if @close_after && pending.length + 1 == @close_after
            @server_io.close
            break
          end
          pending << command
          if @pipelining
            process_pipelined_envelope(pending) if command == 'DATA'
          else
            process_sequential_command(command, pending)
          end
        when 'RSET'
          @server_io.puts "250 2.0.0 OK\r\n"
        when 'QUIT'
          @server_io.puts "221 2.0.0 bye\r\n"
          break
        else
          @server_io.puts "502 5.5.2 unknown\r\n"
        end
      end
    rescue Errno::ECONNRESET, Errno::EPIPE, IOError
      nil
    ensure
      @server_io.close unless @server_io.closed?
    end

    def greet
      if @pipelining
        @server_io.puts "250-servername\r\n250-PIPELINING\r\n250 8BITMIME\r\n"
      else
        @server_io.puts "250-servername\r\n250 8BITMIME\r\n"
      end
    end

    def process_pipelined_envelope(commands)
      @envelope_commands.concat(commands)
      commands.each { |command| write_response(response_for(command)) }
      if @data_response.start_with?('3')
        read_body
        write_response(@final_response)
      end
    ensure
      commands.clear
    end

    def process_sequential_command(command, pending)
      @envelope_commands << command
      write_response(response_for(command))
      return unless command == 'DATA'
      read_body
      write_response(@final_response)
    ensure
      pending.clear if command == 'DATA'
    end

    def response_for(command)
      if command =~ /\ARCPT TO:<([^>]+)>/
        @rcpt_responses.fetch($1, '250 2.1.5 OK')
      elsif command.start_with?('MAIL')
        @mail_response
      else
        @data_response
      end
    end

    def write_response(response)
      lines = response.lines
      lines.each_with_index do |line, index|
        line = line.chomp
        separator = index == lines.length - 1 ? ' ' : '-'
        @server_io.puts "#{line[0, 3]}#{separator}#{line[4..]}\r\n"
      end
    end

    def read_body
      while (line = @server_io.gets)
        line = line.chomp
        break if line == '.'
        @body.concat(line.sub(/\A\./, ''))
      end
    end
  end
end
