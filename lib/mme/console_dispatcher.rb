module Mme
  class ConsoleDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def initialize(driver)
      super
      @engine = nil
    end

    def name
      'MME'
    end

    def commands
      {
        'mme_scan'      => 'Run Nmap scan and execute methodology against target',
        'mme_import'    => 'Import scan results and execute methodology',
        'mme_status'    => 'Show current MME engine status',
        'mme_report'    => 'Generate report (html/json)',
        'mme_playbooks' => 'List available service playbooks',
        'mme_findings'  => 'Display collected findings',
        'mme_stop'      => 'Stop the current MME engine run',
        'mme_help'      => 'Show MME help and usage information'
      }
    end

    # ---- Command Implementations ----

    def cmd_mme_scan(*args)
      if args.empty?
        print_error('Usage: mme_scan <target>')
        print_error('Example: mme_scan 192.168.1.10')
        print_error('Example: mme_scan 192.168.1.0/24')
        return
      end

      unless framework.db.active
        print_error('Database not connected. Run db_connect first.')
        return
      end

      target = args[0]
      engine = get_engine
      engine.scan(target)
    end

    def cmd_mme_import(*args)
      if args.empty?
        print_error('Usage: mme_import <file_path>')
        print_error('Example: mme_import /path/to/nmap_scan.xml')
        return
      end

      unless framework.db.active
        print_error('Database not connected. Run db_connect first.')
        return
      end

      file_path = args[0]
      unless File.exist?(file_path)
        print_error("File not found: #{file_path}")
        return
      end

      engine = get_engine
      engine.import(file_path)
    end

    def cmd_mme_status(*args)
      unless @engine
        print_status('MME engine has not been initialized. Run mme_scan or mme_import first.')
        return
      end

      status = @engine.status
      print_status('')
      print_status('MME Engine Status')
      print_status('=' * 40)
      print_status("State:            #{status[:state]}")
      print_status("Target:           #{status[:target] || 'N/A'}")
      print_status("Elapsed Time:     #{status[:elapsed]}s")
      print_status("Playbooks Loaded: #{status[:playbooks_loaded]}")

      if status[:queue_progress]
        p = status[:queue_progress]
        print_status('')
        print_status('Service Queue:')
        print_status("  Total:       #{p[:total]}")
        print_status("  Completed:   #{p[:completed]}")
        print_status("  Pending:     #{p[:pending]}")
        print_status("  In Progress: #{p[:in_progress]}")
        print_status("  Failed:      #{p[:failed]}")
        print_status("  Skipped:     #{p[:skipped]}")
      end

      if status[:findings_summary]
        s = status[:findings_summary]
        print_status('')
        print_status('Findings:')
        print_status("  Total Evidence: #{s[:total_evidence]}")
        print_status("  Total Findings: #{s[:total_findings]}")
        if s[:by_severity]&.any?
          s[:by_severity].each { |sev, count| print_status("  #{sev.capitalize}: #{count}") }
        end
      end

      if status[:error]
        print_error("Error: #{status[:error]}")
      end
      print_status('=' * 40)
    end

    def cmd_mme_report(*args)
      unless @engine
        print_error('No engine data available. Run mme_scan or mme_import first.')
        return
      end

      format = args[0] || 'html'
      @engine.generate_report(format)
    end

    def cmd_mme_playbooks(*args)
      engine = get_engine
      playbooks = engine.playbooks

      if playbooks.empty?
        print_warning('No playbooks loaded.')
        return
      end

      print_status('')
      print_status('Available MME Playbooks')
      print_status('=' * 60)

      tbl = Rex::Text::Table.new(
        'Header'  => 'Service Playbooks',
        'Indent'  => 2,
        'Columns' => ['Service', 'Ports', 'Steps', 'Description']
      )

      playbooks.each do |pb|
        tbl << [pb.service, pb.ports.join(', '), pb.step_count, pb.description]
      end

      print_line(tbl.to_s)
    end

    def cmd_mme_findings(*args)
      unless @engine
        print_error('No findings available. Run mme_scan or mme_import first.')
        return
      end

      findings = @engine.findings
      if findings.empty?
        print_status('No findings collected yet.')
        return
      end

      print_status('')
      print_status('MME Findings Summary')
      print_status('=' * 70)

      # Group by severity
      grouped = findings.sort.group_by(&:severity)

      grouped.each do |severity, items|
        print_status('')
        print_status("[#{severity.upcase}] (#{items.size} findings)")
        print_status('-' * 50)
        items.each do |f|
          print_status("  #{f.title}")
          print_status("    Host: #{f.host}:#{f.port} (#{f.service})")
          print_status("    Module: #{f.module_path}")
          print_status("    Status: #{f.status}")
          print_status('')
        end
      end
    end

    def cmd_mme_stop(*args)
      unless @engine
        print_status('No engine running.')
        return
      end

      @engine.stop
      print_good('MME engine stop requested.')
    end

    def cmd_mme_help(*args)
      print_status('')
      print_status(Mme::BANNER)
      print_status('=' * 55)
      print_status('')
      print_status('Commands:')
      print_status('  mme_scan <target>        - Scan target and run methodology')
      print_status('  mme_import <file>        - Import scan file and run methodology')
      print_status('  mme_status               - Show engine status')
      print_status('  mme_report [format]      - Generate report (html/json)')
      print_status('  mme_playbooks            - List available playbooks')
      print_status('  mme_findings             - Show collected findings')
      print_status('  mme_stop                 - Stop current run')
      print_status('  mme_help                 - Show this help')
      print_status('')
      print_status('Examples:')
      print_status('  mme_scan 192.168.1.10')
      print_status('  mme_scan 10.0.0.0/24')
      print_status('  mme_import /path/to/nmap_scan.xml')
      print_status('  mme_report html')
      print_status('  mme_report json')
      print_status('')
    end

    # Tab completion
    def cmd_mme_report_tabs(str, words)
      %w[html json pdf]
    end

    private

    def get_engine
      @engine ||= Engine.new(framework, driver.output)
    end
  end
end
