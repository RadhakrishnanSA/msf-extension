require 'open3'
require 'fileutils'

module Mme
  class Scanner
    NMAP_DEFAULT_OPTS = '-sV -sC -T4 --open'
    NMAP_OUTPUT_FORMAT = '-oX'

    def initialize(framework, console_output = nil)
      @framework = framework
      @console_output = console_output
    end

    # Run an Nmap scan against a target and import results
    def nmap_scan(target, nmap_opts = nil, profile = :normal)
      unless nmap_available?
        log_error('Nmap is not installed or not in PATH')
        return []
      end

      unless @framework.db.active
        log_error('Database is not connected. Run db_connect first.')
        return []
      end

      # Create temp file for Nmap XML output
      timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
      output_dir = File.join(mme_data_dir, 'scans')
      FileUtils.mkdir_p(output_dir)
      output_file = File.join(output_dir, "nmap_#{timestamp}.xml")

      # Build Nmap command
      opts = nmap_opts || NMAP_DEFAULT_OPTS
      if profile == :stealth
        opts = opts.gsub('-T4', '-T2')
        opts += ' --max-rate 50' unless opts.include?('--max-rate')
      end
      
      cmd = "nmap #{opts} #{NMAP_OUTPUT_FORMAT} #{output_file} #{target}"

      log_status("Starting Nmap scan: #{cmd}")
      log_status("Target: #{target}")

      # Execute Nmap
      begin
        output, status = Open3.capture2e(cmd)
        unless status.success?
          log_error("Nmap scan failed: #{output}")
          return []
        end
        log_good("Nmap scan completed. Output: #{output_file}")
      rescue Errno::ENOENT
        log_error('Nmap executable not found. Please install Nmap.')
        return []
      rescue => e
        log_error("Nmap scan error: #{e.message}")
        return []
      end

      # Import results
      import_file(output_file, target)
    end

    # Import a scan results file (Nmap XML, Nessus, etc.)
    def import_file(path, target = nil)
      unless File.exist?(path)
        log_error("File not found: #{path}")
        return []
      end

      unless @framework.db.active
        log_error('Database is not connected. Run db_connect first.')
        return []
      end

      log_status("Importing scan results: #{path}")

      begin
        @framework.db.import_file(filename: path)
        log_good("Successfully imported: #{path}")
      rescue => e
        log_error("Import failed: #{e.message}")
        return []
      end

      discover_services(target)
    end

    # Query MSF database for open services in the current workspace
    def discover_services(target = nil)
      unless @framework.db.active
        log_error('Database is not connected')
        return []
      end

      services = []
      workspace = @framework.db.workspace

      # Initialize RangeWalker to filter by target if provided
      range_walker = nil
      if target
        begin
          range_walker = ::Rex::Socket::RangeWalker.new(target)
        rescue => e
          log_warning("Could not parse target range for filtering: #{e.message}")
        end
      end

      @framework.db.services(workspace: workspace).each do |svc|
        next unless svc.state == 'open'
        
        # Filter by target if range walker is initialized
        if range_walker && !range_walker.include?(svc.host.address)
          next
        end

        entry = ServiceEntry.new(
          host: svc.host.address,
          port: svc.port,
          proto: svc.proto,
          name: svc.name || '',
          info: svc.info || '',
          status: :pending
        )
        services << entry
      end

      log_good("Discovered #{services.size} open services across #{services.map(&:host).uniq.size} hosts")
      services
    end

    private

    def nmap_available?
      system('nmap --version > /dev/null 2>&1') || system('nmap --version > NUL 2>&1')
    rescue
      false
    end

    def mme_data_dir
      dir = File.join(Dir.home, '.msf4', 'mme')
      FileUtils.mkdir_p(dir)
      dir
    end

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
