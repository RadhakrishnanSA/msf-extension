require 'timeout'
require_relative 'config'
require_relative 'output_capture'
require_relative 'audit_logger'

module Mme
  # Result of a module execution
  ModuleResult = Struct.new(:module_path, :output, :executed, :timestamp, :error, :duration, :status, keyword_init: true)

  class ModuleRunner
    # Default timeout for module execution (seconds)
    DEFAULT_TIMEOUT = 300

    def initialize(framework, console_output = nil)
      @framework = framework
      @console_output = console_output
    end

    # Run a Metasploit module with given options
    # @param module_path [String] e.g. 'auxiliary/scanner/ftp/ftp_version'
    # @param options [Hash] datastore options e.g. { 'RHOSTS' => '192.168.1.1' }
    # @return [ModuleResult]
    def run(module_path, options = {})
      start_time = Time.now
      log_status("Running module: #{module_path}")

      # Create the module instance
      mod = @framework.modules.create(module_path)
      unless mod
        msg = "Failed to create module: #{module_path}"
        log_error(msg)
        return ModuleResult.new(
          module_path: module_path, output: '', executed: false,
          timestamp: start_time, error: msg, duration: 0,
          status: 'failed'
        )
      end

      # Set datastore options
      options.each do |key, value|
        mod.datastore[key.to_s] = value.to_s
      end

      # Capture output — OutputCapture forwards to @console_output in real-time
      # AND records everything in its internal buffer for later retrieval
      output_capture = Mme::OutputCapture.new(@console_output)

      # Read timeout from config, falling back to the class constant
      timeout = Mme::Config.get('module_timeout') || DEFAULT_TIMEOUT

      begin
        Timeout.timeout(timeout) do
          mod.run_simple(
            'LocalOutput' => output_capture,
            'RunAsJob'    => false,
            'Quiet'       => false
          )
        end
      rescue ::Interrupt
        raise
      rescue Timeout::Error
        duration = Time.now - start_time
        log_error("Module #{module_path} timed out after #{timeout}s")
        return ModuleResult.new(
          module_path: module_path,
          output: output_capture.dump_buffer.to_s,
          executed: false,
          timestamp: start_time,
          error: "Module timed out after #{timeout}s",
          duration: duration,
          status: 'timed_out'
        )
      rescue ::Exception => e
        duration = Time.now - start_time
        log_error("Module #{module_path} error: #{e.message}")
        return ModuleResult.new(
          module_path: module_path,
          output: output_capture.dump_buffer.to_s,
          executed: false,
          timestamp: start_time,
          error: e.message,
          duration: duration,
          status: 'failed'
        )
      end

      duration = Time.now - start_time
      captured = output_capture.dump_buffer.to_s

      log_good("Module #{module_path} completed in #{duration.round(1)}s")

      # Log to audit trail
      Mme::AuditLogger.instance.info("Module #{module_path} completed", duration: duration.round(1), output_lines: captured.lines.size)

      ModuleResult.new(
        module_path: module_path,
        output: captured,
        executed: true,
        timestamp: start_time,
        error: nil,
        duration: duration,
        status: 'success'
      )
    end

    private

    def log_status(msg)
      @console_output ? @console_output.print_status(msg) : $stdout.puts("[*] #{msg}")
    end

    def log_good(msg)
      @console_output ? @console_output.print_good(msg) : $stdout.puts("[+] #{msg}")
    end

    def log_error(msg)
      @console_output ? @console_output.print_error(msg) : $stderr.puts("[-] #{msg}")
    end
  end
end
