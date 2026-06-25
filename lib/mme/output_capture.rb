# frozen_string_literal: true

module Mme
  # Tee-style output capturer that records module output in a buffer
  # AND forwards to a console output object for real-time display.
  #
  # MSF's `run_simple` passes this as `LocalOutput` to modules.
  # Modules (and the MSF framework internals) call various methods on it
  # such as `prompting?`, `input`, `supports_color?`, etc.
  #
  # We implement all known methods explicitly, and use `method_missing`
  # as a safety net so that ANY future MSF method we haven't anticipated
  # will be forwarded to @console_output (or return a safe default)
  # instead of raising NoMethodError and crashing the scan.
  class OutputCapture
    attr_reader :lines

    def initialize(console_output = nil)
      @console_output = console_output
      @buffer = ''
      @lines = []
      @mutex = Mutex.new
    end

    # --- Standard print methods (record + forward) ---

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

    # --- Buffer access ---

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

    # --- MSF UI interface stubs ---
    # These are called by Msf::Module#run_simple, Rex::Ui, and
    # various scanner mixins. We must implement them to avoid
    # NoMethodError crashes.

    def prompting?
      false
    end

    def input
      nil
    end

    def supports_color?
      if @console_output&.respond_to?(:supports_color?)
        @console_output.supports_color?
      else
        false
      end
    end

    def reset_color
      @console_output&.reset_color if @console_output&.respond_to?(:reset_color)
    end

    def auto_color
      if @console_output&.respond_to?(:auto_color)
        @console_output.auto_color
      else
        0
      end
    end

    def update_prompt(*args)
      @console_output&.update_prompt(*args) if @console_output&.respond_to?(:update_prompt)
    end

    # Rex::Ui::Text::Output compatibility
    def write(msg = '')
      record(msg.to_s.chomp, :raw)
      @console_output&.write(msg) if @console_output&.respond_to?(:write)
    end

    # --- Safety net: forward any unknown method ---
    # If MSF calls a method we haven't explicitly defined,
    # forward it to @console_output if it can handle it,
    # otherwise return nil/false to avoid crashing.
    def respond_to_missing?(method_name, include_private = false)
      @console_output&.respond_to?(method_name, include_private) || super
    end

    def method_missing(method_name, *args, &block)
      if @console_output&.respond_to?(method_name)
        @console_output.send(method_name, *args, &block)
      else
        # Return a safe default for predicate methods, nil for everything else
        method_name.to_s.end_with?('?') ? false : nil
      end
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
