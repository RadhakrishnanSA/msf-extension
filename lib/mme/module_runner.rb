module Mme
  # Result of a module execution
  ModuleResult = Struct.new(:module_path, :output, :success, :timestamp, :error, :duration, keyword_init: true)

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
          module_path: module_path, output: '', success: false,
          timestamp: start_time, error: msg, duration: 0
        )
      end

      # Set datastore options
      options.each do |key, value|
        mod.datastore[key.to_s] = value.to_s
      end

      # Capture output
      output_buffer = Rex::Ui::Text::Output::Buffer.new

      begin
        mod.run_simple(
          'LocalOutput' => output_buffer,
          'RunAsJob'    => false,
          'Quiet'       => false
        )
      rescue ::Interrupt
        raise
      rescue ::Exception => e
        duration = Time.now - start_time
        log_error("Module #{module_path} error: #{e.message}")
        return ModuleResult.new(
          module_path: module_path,
          output: output_buffer.dump_buffer.to_s,
          success: false,
          timestamp: start_time,
          error: e.message,
          duration: duration
        )
      end

      duration = Time.now - start_time
      captured = output_buffer.dump_buffer.to_s

      # Forward captured output to console if available
      if @console_output && !captured.empty?
        captured.each_line { |line| @console_output.print_line(line.chomp) }
      end

      log_good("Module #{module_path} completed in #{duration.round(1)}s")

      ModuleResult.new(
        module_path: module_path,
        output: captured,
        success: true,
        timestamp: start_time,
        error: nil,
        duration: duration
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
