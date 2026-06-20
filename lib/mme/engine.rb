require_relative 'state_manager'
require_relative 'audit_logger'

module Mme
  class Engine
    STATES = %i[idle scanning importing running completed stopped error].freeze

    attr_reader :state, :service_queue, :start_time, :end_time,
                :target, :playbook_results, :error_message

    def initialize(framework, console_output = nil)
      @framework = framework
      @console_output = console_output
      @state = :idle
      @state_manager = StateManager.new
      @session_id = @state_manager.session_id
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
      @opts = {}
      @mutex = Mutex.new

      # Load playbooks
      @playbook_engine.load_playbooks(mme_playbook_dir)
    end

    # Full workflow: Nmap scan → discover → queue → execute → report
    def scan(target, opts = {})
      opts = { nmap_opts: opts } if opts.is_a?(String) || opts.nil?
      @target = target
      @start_time = Time.now
      
      @state_manager = StateManager.new
      @session_id = @state_manager.session_id
      @stop_requested = false
      @playbook_results = []
      @evidence_collector.clear

      log_banner
      log_good("Starting methodology scan against: #{target} (Threads: #{opts[:threads] || 1}, Profile: #{opts[:profile] || :normal})")

      begin
        # Step 1: Nmap scan
        log_status('[Phase 1/5] Running Nmap scan...')
        services = @scanner.nmap_scan(target, opts[:nmap_opts], opts[:profile])

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
        @state_manager.save(@target, @start_time, @opts, @service_queue)
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

    def resume(session_id)
      @state_manager = StateManager.new(session_id)
      @service_queue = @state_manager.load

      if @service_queue.nil?
        log_error("Session not found or invalid: #{session_id}")
        return
      end

      @target = @state_manager.target
      @start_time = @state_manager.start_time
      @opts = @state_manager.options
      @state = :running
      @stop_requested = false
      @playbook_results = []
      @evidence_collector.clear

      log_banner
      log_good("Resuming session #{session_id} for target: #{@target}")
      
      # Jump straight to queue execution since we already have the queue built
      process_service_queue

      return if @stop_requested

      log_status('[Phase 4/5] Storing evidence to database...')
      @evidence_collector.store_to_db

      log_status('[Phase 5/5] Generating report...')
      html_path = generate_report('html')
      generate_report('json')
      generate_report('md')

      @state = :completed
      @end_time = Time.now

      log_completion_summary(html_path)
    rescue ::Interrupt
      log_warning('Resume interrupted by user.')
      @state = :stopped
      @state_manager.save(@target, @start_time, @opts, @service_queue)
    rescue => e
      log_error("Engine error during resume: #{e.message}")
      @error_message = e.message
      @state = :error
      @end_time = Time.now
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
      @state_manager.save(@target, @start_time, @opts, @service_queue) if @start_time
      log_warning('Stop requested. Finishing current step and saving state...')
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
      when 'md', 'markdown'
        path = @report_generator.generate_markdown(findings, evidence, metadata)
        log_good("Markdown report saved: #{path}")
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
      html_path = generate_report('html')
      generate_report('json')
      md_path = generate_report('md')

      @state = :completed
      @end_time = Time.now

      log_completion_summary(html_path, md_path)
    end

    def process_service_queue
      requested_threads = @opts[:threads] || 1
      requested_threads = 1 if requested_threads < 1
      
      global_max = Config.get('global_max_threads') || 10
      if requested_threads > global_max
        log_warning("[!] Requested #{requested_threads} threads, but global max is #{global_max}. Capping at #{global_max}.")
        thread_count = global_max
      else
        thread_count = requested_threads
      end
      
      if thread_count == 1
        while (service_entry = @service_queue.next_service)
          break if @stop_requested
          process_service_with_logging(service_entry)
        end
      else
        threads = []
        log_status("Spinning up #{thread_count} parallel threads...")
        thread_count.times do
          threads << Thread.new do
            while (service_entry = @service_queue.next_service)
              break if @stop_requested
              process_service_with_logging(service_entry)
            end
          end
        end
        threads.each(&:join)
      end
    end

    def process_service_with_logging(service_entry)
      progress = @service_queue.progress
      idx = progress[:completed] + progress[:failed] + progress[:skipped] + 1
      total = progress[:total]

      @mutex.synchronize do
        log_status("\n#{'=' * 60}")
        log_status("[#{idx}/#{total}] Processing #{service_entry.name.upcase} on #{service_entry.host}:#{service_entry.port}")
        log_status('=' * 60)
      end

      process_service(service_entry)
    end

    def process_service(service_entry)
      # Check if this host has been marked unreachable
      @unreachable_hosts ||= {}
      if @unreachable_hosts[service_entry.host]
        log_warning("[!] Skipping #{service_entry.name} on #{service_entry.host} (host marked unreachable)")
        @service_queue.skip(service_entry)
        return
      end

      playbook = @playbook_engine.find_playbook(service_entry.name, service_entry.port)

      unless playbook
        log_warning("No playbook found for service: #{service_entry.name} (port #{service_entry.port})")
        @service_queue.skip(service_entry)
        return
      end

      begin
        result = @playbook_engine.execute(playbook, service_entry, @evidence_collector, @opts)
        @mutex.synchronize { @playbook_results << result }
        @service_queue.complete(service_entry)
        @state_manager.save(@target, @start_time, @opts, @service_queue)
      rescue => e
        if e.class.name.include?('ConnectionRefused') || e.class.name.include?('ConnectionTimeout')
          @connection_errors ||= Hash.new(0)
          @connection_errors[service_entry.host] += 1
          
          if @connection_errors[service_entry.host] >= 3
            log_error("[!] Host #{service_entry.host} appears unreachable (3 consecutive errors). Skipping remaining services.")
            @unreachable_hosts[service_entry.host] = true
          end
        end
        
        log_error("Playbook execution failed for #{service_entry}: #{e.message}")
        @service_queue.fail(service_entry)
        @state_manager.save(@target, @start_time, @opts, @service_queue)
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

    def log_completion_summary(html_path = nil, md_path = nil)
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

      log_status('-' * 60)
      log_status('Modules Executed & Findings:')
      @playbook_results.each do |pr|
        log_status("  Service: #{pr.service_entry.name.upcase} (#{pr.service_entry.host}:#{pr.service_entry.port})")
        pr.step_results.each do |sr|
          status_icon = sr.executed ? '[+]' : '[-]'
          log_status("    #{status_icon} #{sr.module_path}")
        end
      end
      
      # Clean up state file since we finished normally
      @state_manager.delete
      
      if html_path || md_path
        log_good("Report(s) generated successfully!")
        log_good("HTML: file://#{html_path}") if html_path
        log_good("Markdown: file://#{md_path}") if md_path
      end
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
      AuditLogger.instance.info(msg) unless msg.strip.empty? || msg.include?('═')
      @console_output ? @console_output.print_status(msg) : $stdout.puts("[*] #{msg}")
    end

    def log_good(msg)
      AuditLogger.instance.info(msg, status: 'success')
      @console_output ? @console_output.print_good(msg) : $stdout.puts("[+] #{msg}")
    end

    def log_error(msg)
      AuditLogger.instance.error(msg)
      @console_output ? @console_output.print_error(msg) : $stderr.puts("[-] #{msg}")
    end

    def log_warning(msg)
      AuditLogger.instance.warn(msg)
      @console_output ? @console_output.print_warning(msg) : $stderr.puts("[!] #{msg}")
    end
  end
end
