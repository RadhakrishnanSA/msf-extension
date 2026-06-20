module Mme
  class OutputCapture
    attr_reader :buffer, :lines

    def initialize(console_output = nil)
      @console_output = console_output
      @buffer = ''
      @lines = []
      @mutex = Mutex.new
    end

    def print_line(msg = '')
      record(msg, :info)
      @console_output&.print_line(msg)
    end

    def print_status(msg = '')
      record("[*] #{msg}", :status)
      @console_output&.print_status(msg)
    end

    def print_good(msg = '')
      record("[+] #{msg}", :good)
      @console_output&.print_good(msg)
    end

    def print_error(msg = '')
      record("[-] #{msg}", :error)
      @console_output&.print_error(msg)
    end

    def print_warning(msg = '')
      record("[!] #{msg}", :warning)
      @console_output&.print_warning(msg)
    end

    # For compatibility with Rex::Ui::Text::Output interface
    def print(msg = '')
      record(msg.to_s.chomp, :raw)
      @console_output&.print(msg)
    end

    def flush
      @console_output&.flush
    end

    def dump_buffer
      @mutex.synchronize { @buffer.dup }
    end

    def dump_lines
      @mutex.synchronize { @lines.dup }
    end

    def clear
      @mutex.synchronize do
        @buffer = ''
        @lines = []
      end
    end

    def empty?
      @mutex.synchronize { @buffer.empty? }
    end

    private

    def record(msg, level)
      @mutex.synchronize do
        entry = { timestamp: Time.now, level: level, message: msg.to_s }
        @lines << entry
        @buffer << msg.to_s << "\n"
      end
    end
  end
end
