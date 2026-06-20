require 'fileutils'

module Mme
  class Engine
    STATES = %i[idle scanning importing running completed stopped error].freeze

    attr_reader :state, :service_queue, :start_time, :end_time,
                :target, :playbook_results, :error_message

    def initialize(framework, console_output = nil)
      @framework = framework
      @console_output = console_output
      @state = :idle
      @scanner = Scanner.new(framework, console_output)
      @service_queue = ServiceQueue.new
      @playbook_engine = PlaybookEngine.new(framework, console_output)
      @evidence_collector = EvidenceCollector.new(framework)
      @report_generator = ReportGenerator.new(mme_template_dir)
      @playbook_results = []
      @stop_requested = false
      @target = nil
      @start_time = nil
      @end_time = nil
      @error_message = nil

      # Load playbooks
      @playbook_engine.load_playbooks(mme_playbook_dir)
    end

    # Full workflow: Nmap scan → discover → queue → execute → report
    def scan(target)
      @target = target
      @state = :scanning
      @start_time = Time.now
      @stop_requested = false
      @playbook_results = []
      @evidence_collector.clear

      log_banner
      log_good("Starting methodology scan against: #{target}")

      begin
        # Step 1: Nmap scan
        log_status('[Phase 1/5] Running Nmap scan...')
        services = @scanner.nmap_scan(target)

        if services.empty?
          log_error('No open services discovered. Aborting.')
          @state = :completed
          @end_time = Time.now
          return
        end

        # Continue with methodology
        run_methodology(services)
      rescue ::Interrupt
        log_warning('Scan interrupted by user.')
        @state = :stopped
        @end_time = Time.now
      rescue => e
        log_error("Engine error: #{e.message}")
        @error_message = e.message
        @state = :error
        @end_time = Time.now
      end
    end

    # Import scan file → discover → queue → execute → report
    def import(file_path)
      @target = file_path
      @state = :importing
      @start_time = Time.now
      @stop_requested = false
      @playbook_results = []
      @evidence_collector.clear

      log_banner
      log_good("Importing scan results: #{file_path}")

      begin
        # Step 1: Import
        log_status('[Phase 1/5] Importing scan results...')
        services = @scanner.import_file(file_path)

        if services.empty?
          log_error('No open services found in import. Aborting.')
          @state = :completed
          @end_time = Time.now
          return
        end

        # Continue with methodology
        run_methodology(services)
      rescue ::Interrupt
        log_warning('Import interrupted by user.')
        @state = :stopped
        @end_time = Time.now
      rescue => e
        log_error("Engine error: #{e.message}")
        @error_message = e.message
        @state = :error
        @end_time = Time.now
      end
    end

    def status
      {
        state: @state,
        target: @target,
        start_time: @start_time,
        elapsed: @start_time ? ((@end_time || Time.now) - @start_time).round(1) : 0,
        queue_progress: @service_queue.progress,
        findings_summary: @evidence_collector.summary,
        playbooks_loaded: @playbook_engine.playbook_count,
        error: @error_message
      }
    end

    def stop
      @stop_requested = true
      @state = :stopped
      log_warning('Stop requested. Finishing current step...')
    end

    def generate_report(format = 'html')
      findings = @evidence_collector.findings
      evidence = @evidence_collector.evidence_list
      metadata = build_report_metadata

      case format.to_s.downcase
      when 'html'
        path = @report_generator.generate_html(findings, evidence, metadata)
        log_good("HTML report saved: #{path}")
        path
      when 'json'
        path = @report_generator.generate_json(findings, evidence, metadata)
        log_good("JSON report saved: #{path}")
        path
      when 'pdf'
        log_warning('PDF report generation is not yet implemented. Use HTML or JSON.')
        nil
      else
        log_error("Unknown report format: #{format}. Use html, json, or pdf.")
        nil
      end
    end

    def playbooks
      @playbook_engine.list_playbooks
    end

    def findings_summary
      @evidence_collector.summary
    end

    def findings
      @evidence_collector.findings
    end

    private

    def run_methodology(services)
      # Step 2: Build service queue
      log_status('[Phase 2/5] Building service queue...')
      services.each { |svc| @service_queue.add(svc) }
      log_good("Service queue built: #{@service_queue.size} services across #{@service_queue.hosts.size} hosts")
      log_status(@service_queue.to_s)

      # Step 3: Execute playbooks
      log_status('[Phase 3/5] Executing service playbooks...')
      @state = :running
      process_service_queue

      return if @stop_requested

      # Step 4: Store evidence
      log_status('[Phase 4/5] Storing evidence to database...')
      @evidence_collector.store_to_db

      # Step 5: Generate report
      log_status('[Phase 5/5] Generating report...')
      generate_report('html')
      generate_report('json')

      @state = :completed
      @end_time = Time.now

      log_completion_summary
    end

    def process_service_queue
      while (service_entry = @service_queue.next_service)
        break if @stop_requested

        progress = @service_queue.progress
        idx = progress[:completed] + progress[:failed] + progress[:skipped] + 1
        total = progress[:total]

        log_status("\n#{'=' * 60}")
        log_status("[#{idx}/#{total}] Processing #{service_entry.name.upcase} on #{service_entry.host}:#{service_entry.port}")
        log_status('=' * 60)

        process_service(service_entry)
      end
    end

    def process_service(service_entry)
      playbook = @playbook_engine.find_playbook(service_entry.name, service_entry.port)

      unless playbook
        log_warning("No playbook found for service: #{service_entry.name} (port #{service_entry.port})")
        @service_queue.skip(service_entry)
        return
      end

      begin
        result = @playbook_engine.execute(playbook, service_entry, @evidence_collector)
        @playbook_results << result
        @service_queue.complete(service_entry)
      rescue => e
        log_error("Playbook execution failed for #{service_entry}: #{e.message}")
        @service_queue.fail(service_entry)
      end
    end

    def build_report_metadata
      {
        tool_name: Mme::NAME,
        tool_version: Mme::VERSION,
        target: @target,
        start_time: @start_time,
        end_time: @end_time || Time.now,
        duration: @start_time ? ((@end_time || Time.now) - @start_time).round(1) : 0,
        hosts_scanned: @service_queue.hosts.size,
        services_found: @service_queue.size,
        queue_progress: @service_queue.progress,
        state: @state
      }
    end

    def log_banner
      log_status('')
      log_status('╔══════════════════════════════════════════════════════╗')
      log_status("║     Metasploit Methodology Engine (MME) v#{Mme::VERSION}       ║")
      log_status('║     Automated Penetration Testing Methodology        ║')
      log_status('╚══════════════════════════════════════════════════════╝')
      log_status('')
    end

    def log_completion_summary
      duration = (@end_time - @start_time).round(1)
      progress = @service_queue.progress
      summary = @evidence_collector.summary

      log_status('')
      log_status('=' * 60)
      log_good('METHODOLOGY COMPLETE')
      log_status('=' * 60)
      log_status("Duration:          #{duration}s")
      log_status("Services Processed: #{progress[:completed]}/#{progress[:total]}")
      log_status("Services Skipped:   #{progress[:skipped]}")
      log_status("Services Failed:    #{progress[:failed]}")
      log_status("Total Findings:     #{summary[:total_findings]}")

      if summary[:by_severity].any?
        log_status('Findings by Severity:')
        summary[:by_severity].each do |sev, count|
          log_status("  #{sev.capitalize}: #{count}")
        end
      end

      log_status('=' * 60)
    end

    def mme_base_dir
      # This will be resolved at load time based on plugin location
      @mme_base_dir ||= begin
        # Try to find the MME installation directory
        candidates = [
          File.join(Dir.home, '.msf4', 'mme'),
          File.join(Dir.home, '.msf4', 'plugins', 'mme'),
          File.expand_path('../../', __dir__)
        ]
        candidates.find { |d| File.directory?(d) } || candidates.first
      end
    end

    def mme_playbook_dir
      File.join(mme_base_dir, 'playbooks')
    end

    def mme_template_dir
      File.join(mme_base_dir, 'templates')
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

    def log_warning(msg)
      @console_output ? @console_output.print_warning(msg) : $stderr.puts("[!] #{msg}")
    end
  end
end
