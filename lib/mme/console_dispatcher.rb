require_relative 'config'
require_relative 'scope'
require_relative 'state_manager'

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
        'mme_ui'        => 'Launch the interactive MME configuration wizard',
        'mme_import'    => 'Import scan results and execute methodology',
        'mme_status'    => 'Show current MME engine status',
        'mme_report'    => 'Generate report (html/json)',
        'mme_playbooks' => 'List available service playbooks',
        'mme_findings'  => 'Display collected findings',
        'mme_stop'      => 'Stop the current MME engine run',
        'mme_sessions'  => 'List resumable MME sessions',
        'mme_resume'    => 'Resume a paused MME session',
        'mme_config'    => 'Get or set MME configuration values',
        'mme_scope'     => 'Manage the target scope list',
        'mme_help'      => 'Show MME help and usage information'
      }
    end

    # ---- Command Implementations ----

    def cmd_mme_scan(*args)
      if args.empty?
        print_error('Usage: mme_scan <target> [options]')
        print_error('Options:')
        print_error('  --threads N      Number of parallel threads (default: 1)')
        print_error('  --profile NAME   Scan profile: normal, stealth (default: normal)')
        print_error('  --brute          Enable brute-force/login modules (disabled by default)')
        print_error('  -p PORTS         Ports to scan (e.g. -p 80,443)')
        print_error('Example: mme_scan 192.168.1.10 --threads 3 --profile stealth --brute')
        return
      end

      unless framework.db.active
        print_error('Database not connected. Run db_connect first.')
        return
      end

      target = args.shift
      force = false
      opts = { 
        threads: Config.get('threads'), 
        profile: Config.get('profile').to_sym, 
        brute: Config.get('brute'), 
        nmap_opts: [] 
      }
      
      while (arg = args.shift)
        case arg
        when '--threads'
          opts[:threads] = args.shift.to_i
        when '--profile'
          opts[:profile] = args.shift.to_s.downcase.to_sym
        when '--brute'
          opts[:brute] = true
        when '--no-brute'
          print_warning('[!] --no-brute is deprecated. Brute-forcing is now disabled by default. Use --brute to enable it.')
          opts[:brute] = false
        when '--force'
          force = true
        else
          opts[:nmap_opts] << arg
        end
      end
      
      opts[:nmap_opts] = opts[:nmap_opts].empty? ? nil : opts[:nmap_opts].join(' ')

      # Scope Enforcement
      scope = Scope.new(framework.db.workspace.name)
      if scope.empty?
        unless @scope_warning_printed
          print_warning('[!] No scope defined for this workspace. All targets will be allowed. Use `mme_scope add <target>` to set scope boundaries.')
          @scope_warning_printed = true
        end
      else
        unless scope.include?(target) || force
          print_error("[-] OUT OF SCOPE: Target #{target} is not in the defined scope for workspace #{framework.db.workspace.name}.")
          print_error("[-] To bypass this check, use the --force flag.")
          return
        end
      end

      engine = get_engine
      engine.scan(target, opts)
    end

    def cmd_mme_ui(*args)
      print_status('')
      print_status('=' * 50)
      print_status(' MME Interactive Configuration Wizard')
      print_status('=' * 50)
      print_status('')

      # Target
      target = ''
      while target.empty?
        print('Target IP or CIDR (e.g. 192.168.1.10): ')
        target = gets.to_s.strip
      end

      # Threads
      print('Number of parallel threads? [1]: ')
      threads_in = gets.to_s.strip
      threads = threads_in.empty? ? 1 : threads_in.to_i

      # Stealth
      print('Enable Stealth Mode? (Slower Nmap, Adds Delays) [y/N]: ')
      stealth_in = gets.to_s.strip.downcase
      profile = (stealth_in == 'y' || stealth_in == 'yes') ? :stealth : :normal

      # Brute-force
      print('Enable Brute-Forcing / Login Attempts? (Slower, noisy) [y/N]: ')
      brute_in = gets.to_s.strip.downcase
      brute = (brute_in == 'y' || brute_in == 'yes') ? true : false

      print_status('')
      print_status('Building configuration...')
      
      opts = {
        threads: threads,
        profile: profile,
        brute: brute,
        nmap_opts: nil
      }

      print_status("Launching: mme_scan #{target} --threads #{threads} --profile #{profile} #{brute ? '--brute' : ''}")
      print_status('=' * 50)
      
      engine = get_engine
      engine.scan(target, opts)
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

    def cmd_mme_config(*args)
      if args.empty? || args[0] == 'list'
        print_status('')
        print_status('MME Configuration')
        print_status('=' * 40)
        Config.all.each { |k, v| print_status("#{k.ljust(20)} : #{v}") }
        print_status('=' * 40)
        return
      end

      action = args.shift
      key = args.shift

      if action == 'get'
        if key
          val = Config.get(key)
          print_status("#{key} = #{val}")
        else
          print_error('Usage: mme_config get <key>')
        end
      elsif action == 'set'
        val = args.join(' ')
        if key && !val.empty?
          Config.set(key, val)
          print_good("Set #{key} to #{Config.get(key)}")
        else
          print_error('Usage: mme_config set <key> <value>')
        end
      else
        print_error("Unknown action: #{action}. Use 'get', 'set', or 'list'.")
      end
    end

    def cmd_mme_sessions(*args)
      sessions = StateManager.list_sessions
      if sessions.empty?
        print_status('No resumable sessions found.')
        return
      end

      print_status('')
      print_status('Resumable MME Sessions')
      print_status('=' * 80)
      
      tbl = Rex::Text::Table.new(
        'Header'  => 'Sessions',
        'Indent'  => 2,
        'Columns' => ['Session ID', 'Target', 'Progress', 'Last Updated']
      )

      sessions.each do |s|
        progress = "#{s[:queue_completed]}/#{s[:queue_total]} (#{(s[:queue_completed].to_f / s[:queue_total] * 100).round(1)}%)"
        tbl << [s[:id], s[:target], progress, s[:last_updated].strftime('%Y-%m-%d %H:%M:%S')]
      end

      print_line(tbl.to_s)
      print_status("Use `mme_resume <session_id>` to continue a session.")
    end

    def cmd_mme_resume(*args)
      if args.empty?
        print_error('Usage: mme_resume <session_id>')
        return
      end

      unless framework.db.active
        print_error('Database not connected. Run db_connect first.')
        return
      end

      session_id = args.shift
      engine = get_engine
      engine.resume(session_id)
    end

    def cmd_mme_scope(*args)
      unless framework.db.active
        print_error('Database not connected. Run db_connect first to determine workspace scope.')
        return
      end

      scope = Scope.new(framework.db.workspace.name)

      if args.empty? || args[0] == 'list'
        entries = scope.list
        print_status('')
        print_status("Scope for workspace: #{framework.db.workspace.name}")
        print_status('=' * 40)
        if entries.empty?
          print_status('  (No scope defined. All targets allowed.)')
        else
          entries.each { |e| print_status("  #{e}") }
        end
        print_status('=' * 40)
        return
      end

      action = args.shift
      target = args.shift

      case action
      when 'add'
        if target
          if scope.add(target)
            print_good("Added #{target} to scope.")
          else
            print_warning("#{target} is already in scope.")
          end
        else
          print_error('Usage: mme_scope add <target>')
        end
      when 'remove'
        if target
          if scope.remove(target)
            print_good("Removed #{target} from scope.")
          else
            print_warning("#{target} not found in scope.")
          end
        else
          print_error('Usage: mme_scope remove <target>')
        end
      when 'clear'
        scope.clear
        print_good('Scope cleared.')
      else
        print_error("Unknown action: #{action}. Use 'add', 'remove', 'list', or 'clear'.")
      end
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
      print_status('  mme_sessions             - List paused sessions')
      print_status('  mme_resume <id>          - Resume a paused session')
      print_status('  mme_scope                - Manage target scope')
      print_status('  mme_config               - Manage configuration')
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
