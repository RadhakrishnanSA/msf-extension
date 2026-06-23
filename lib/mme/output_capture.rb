# frozen_string_literal: true

begin
  require 'rex/ui/text/output/buffer'
rescue LoadError
  # Fallback if somehow not loaded
end

module Mme
  # Output capture utility that satisfies MSF's LocalOutput requirements
  class OutputCapture < (defined?(Rex::Ui::Text::Output::Buffer) ? Rex::Ui::Text::Output::Buffer : Object)
    attr_reader :lines

    def initialize(console_output = nil)
      super() if defined?(Rex::Ui::Text::Output::Buffer)
      @console_output = console_output
      @custom_buffer = ''
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

    def print(msg = '')
      record(msg.to_s.chomp, :raw)
      @console_output&.print(msg)
    end

    def flush
      @console_output&.flush
    end

    def dump_buffer
      @mutex.synchronize { @custom_buffer.dup }
    end

    def dump_lines
      @mutex.synchronize { @lines.dup }
    end

    def clear
      @mutex.synchronize do
        @custom_buffer = ''
        @lines = []
      end
    end

    def empty?
      @mutex.synchronize { @custom_buffer.empty? }
    end

    # --- MSF UI Interface Stubs ---

    def prompting?
      false
    end

    def input
      nil
    end

    def supports_color?
      @console_output ? @console_output.supports_color? : false
    end

    def reset_color
      @console_output&.reset_color
    end

    private

    def record(msg, level)
      @mutex.synchronize do
        entry = { timestamp: Time.now, level: level, message: msg.to_s }
        @lines << entry
        @custom_buffer << msg.to_s << "\n"
      end
    end
  end
end
