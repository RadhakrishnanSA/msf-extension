require 'optparse'
require_relative 'config'
require_relative 'scope'
require_relative 'state_manager'
require_relative 'playbook'
require_relative 'validator'

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
        'mme_checkpoints'=> 'List resumable MME state sessions',
        'mme_sessions'  => 'List actual MSF sessions gained via MME',
        'mme_resume'    => 'Resume a paused MME session',
        'mme_config'    => 'Get or set MME configuration values',
        'mme_scope'     => 'Manage the target scope list',
        'mme_doctor'    => 'Run environment health checks',
        'mme_export'    => 'Export findings to external platform (defectdojo)',
        'mme_help'      => 'Show MME help and usage information'
      }
    end

    # ---- Command Implementations ----

    def cmd_mme_scan(*args)
      opts = {
        threads: Config.get('threads'),
        profile: Config.get('profile').to_sym,
        brute: Config.get('brute'),
        nmap_opts: nil,
        force: false,
        webhook: nil,
        show_creds: false
      }

      parser = OptionParser.new do |o|
        o.banner = 'Usage: mme_scan <target> [options]'
        o.separator ''
        o.separator 'Options:'

        o.on('--threads N', Integer, "Number of parallel threads (default: #{opts[:threads]})") { |v| opts[:threads] = v }
        o.on('--profile NAME', String, 'Scan profile: normal, stealth (default: normal)') { |v| opts[:profile] = v.downcase.to_sym }
        o.on('--brute', 'Enable brute-force/login modules') { opts[:brute] = true }
        o.on('--force', 'Bypass scope enforcement') { opts[:force] = true }
        o.on('--webhook URL', String, 'POST summary to webhook URL on completion') { |v| opts[:webhook] = v }
        o.on('--show-creds', 'Show full credentials in reports (default: redacted)') { opts[:show_creds] = true }
        o.on('--dry-run', 'Simulation mode. Map methodology without executing modules.') { opts[:dry_run] = true }
        o.on('--auto-confirm-exploits', 'Unattended mode: auto-run exploits (requires --i-have-authorization)') { opts[:auto_confirm] = true }
        o.on('--i-have-authorization', 'Safety confirmation for unattended exploit runs') { opts[:auth_confirmed] = true }
        o.on('--no-pingsweep', 'Skip Phase 0 ping sweep and queue range targets directly') { opts[:no_pingsweep] = true }
        o.on('--no-subdomain-enum', 'Skip Phase 0 subdomain enumeration for domain targets') { opts[:no_subdomain_enum] = true }
        o.on('--passive-only', 'Skip Phase 0 active DNS brute-forcing') { opts[:passive_only] = true }
        o.on('--subdomain-wordlist PATH', String, 'Custom wordlist for DNS brute-forcing') { |v| opts[:subdomain_wordlist] = v }
        o.on('-p PORTS', String, 'Ports to scan') { |v| opts[:nmap_opts] = "-p #{v}" }
        o.on('-h', '--help', 'Show this help') do
          print_line(o.to_s)
          return
        end
      end

      # Parse known flags, leaving target and unknown nmap flags
      remaining = []
      begin
        remaining = parser.parse(args)
      rescue OptionParser::InvalidOption => e
        # Unknown flags might be nmap options — collect them
        remaining = e.args + args
      rescue OptionParser::MissingArgument => e
        print_error(e.message)
        return
      end

      target = remaining.shift
      if target.nil? || target.empty?
        print_line(parser.to_s)
        return
      end

      # Extra remaining args are nmap options
      if remaining.any?
        nmap_extra = remaining.join(' ')
        opts[:nmap_opts] = opts[:nmap_opts] ? "#{opts[:nmap_opts]} #{nmap_extra}" : nmap_extra
      end

      unless framework.db.active
        print_error('Database not connected. Run db_connect first.')
        return
      end

      # Validate inputs
      if defined?(Validator) && Validator.respond_to?(:validate_target!)
        begin
          Validator.validate_target!(target)
        rescue => e
          print_error(e.message)
          return
        end
      end

      # Scope Enforcement
      scope = Scope.new(framework.db.workspace.name)
      if scope.empty?
        unless @scope_warning_printed
          print_warning('[!] No scope defined for this workspace. All targets will be allowed.')
          @scope_warning_printed = true
        end
      else
        unless scope.include?(target) || opts[:force]
          print_error("OUT OF SCOPE: Target #{target} is not in the defined scope.")
          print_error('To bypass this check, use the --force flag.')
          return
        end
      end

      # Safety Check for auto-confirmation
      if opts[:auto_confirm]
        unless opts[:auth_confirmed]
          print_error('SAFETY ABORT: --auto-confirm-exploits requires --i-have-authorization')
          return
        end
        print_warning('=' * 60)
        print_warning('! DANGER: UNATTENDED EXPLOIT EXECUTION ENABLED !')
        print_warning('=' * 60)
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

      # Validate file path
      begin
        Validator.validate_file_path!(file_path)
      rescue Validator::ValidationError => e
        print_error(e.message)
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

      # Validate report format
      begin
        format = Validator.validate_report_format!(format)
      rescue Validator::ValidationError => e
        print_error(e.message)
        return
      end

      @engine.generate_report(format)
    end

    def cmd_mme_playbooks(*args)
      engine = get_engine
      
      if args.include?('--gaps')
        gaps = engine.unmatched_services || []
        if gaps.empty?
          print_status("No coverage gaps detected from the last run.")
        else
          print_warning("Services without matching playbooks:")
          gaps.each do |svc|
            print_status("  - #{svc.host}:#{svc.port} (#{svc.name})")
          end
        end
        return
      end

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

    def cmd_mme_checkpoints(*args)
      sessions = StateManager.list_sessions
      if sessions.empty?
        print_status('No resumable checkpoints found.')
        return
      end

      print_status('')
      print_status('Resumable MME Checkpoints')
      print_status('=' * 80)
      
      tbl = Rex::Text::Table.new(
        'Header'  => 'Checkpoints',
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

    def cmd_mme_sessions(*args)
      engine = get_engine
      sessions = engine.gained_sessions || []
      
      if sessions.empty?
        print_status("No MSF sessions gained via MME yet.")
        return
      end

      print_status('')
      print_status('MSF Sessions Acquired via MME')
      print_status('=' * 80)
      
      sessions.each do |s|
        print_status("Session #{s[:session_id]} - #{s[:info]}")
        print_status("  Host: #{s[:host]}:#{s[:port]}")
        print_status("  Via:  #{s[:module]}")
        print_status('')
      end
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

      # Validate session ID
      begin
        Validator.validate_session_id!(session_id)
      rescue Validator::ValidationError => e
        print_error(e.message)
        return
      end

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
            print_good("Removed #{target} to scope.")
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

    def cmd_mme_doctor(*args)
      print_status('')
      print_status('MME Doctor — Environment Health Check')
      print_status('=' * 50)
      checks_passed = 0
      checks_failed = 0

      # 1. Nmap installed
      nmap_ok = system('nmap --version > /dev/null 2>&1') || system('nmap --version > NUL 2>&1') rescue false
      if nmap_ok
        print_good('[✓] Nmap is installed and on PATH')
        checks_passed += 1
      else
        print_error('[✗] Nmap is NOT installed or not on PATH')
        checks_failed += 1
      end

      # 2. Database connection
      if framework.db.active
        print_good('[✓] MSF database is connected')
        checks_passed += 1
      else
        print_error('[✗] MSF database is NOT connected (run db_connect)')
        checks_failed += 1
      end

      # 3. MME data directory writable
      mme_dir = File.join(Dir.home, '.msf4', 'mme')
      if File.directory?(mme_dir) && File.writable?(mme_dir)
        print_good("[✓] MME data directory is writable: #{mme_dir}")
        checks_passed += 1
      else
        print_error("[✗] MME data directory missing or not writable: #{mme_dir}")
        checks_failed += 1
      end

      # 4. Playbook directory readable and all playbooks valid
      engine = get_engine
      pb_dir = File.join(mme_dir, 'playbooks')
      if File.directory?(pb_dir) && File.readable?(pb_dir)
        pb_files = Dir.glob(File.join(pb_dir, '*.yml'))
        pb_errors = []
        pb_files.each do |f|
          begin
            Mme::Playbook.load_from_file(f)
          rescue => e
            pb_errors << "  #{File.basename(f)}: #{e.message}"
          end
        end
        if pb_errors.empty?
          print_good("[✓] #{pb_files.size} playbooks loaded successfully")
          checks_passed += 1
        else
          print_error("[✗] #{pb_errors.size} playbook(s) failed validation:")
          pb_errors.each { |e| print_error(e) }
          checks_failed += 1
        end
      else
        print_error("[✗] Playbook directory missing or not readable: #{pb_dir}")
        checks_failed += 1
      end

      # 5. Wordlist paths from config
      wordlist_paths = Config.get('wordlist_paths') || []
      existing_wl = wordlist_paths.select { |p| File.directory?(p) }
      if existing_wl.any?
        print_good("[✓] Wordlist directories found: #{existing_wl.join(', ')}")
        checks_passed += 1
      else
        print_warning('[!] No configured wordlist directories found (brute-force may fail)')
        checks_failed += 1
      end

      # 6. Config file
      if File.exist?(Config.config_file)
        print_good("[✓] Config file exists: #{Config.config_file}")
        checks_passed += 1
      else
        print_warning('[!] Config file not found (will use defaults)')
        checks_failed += 1
      end

      print_status('')
      print_status("Results: #{checks_passed} passed, #{checks_failed} failed")
      print_status('=' * 50)
    end

    def cmd_mme_export(*args)
      if args.empty?
        print_error('Usage: mme_export <format> [destination]')
        print_error('Formats: defectdojo')
        print_error('Example: mme_export defectdojo')
        print_error('')
        print_error('Configure first:')
        print_error('  mme_config set defectdojo_url https://your-instance.com/api/v2')
        print_error('  mme_config set defectdojo_token your-api-token')
        return
      end

      unless @engine
        print_error('No findings available. Run mme_scan first.')
        return
      end

      format = args.shift
      case format.downcase
      when 'defectdojo'
        export_to_defectdojo
      else
        print_error("Unknown export format: #{format}. Available: defectdojo")
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
      print_status('  mme_report [format]      - Generate report (html/json/md/pdf)')
      print_status('  mme_playbooks            - List available playbooks')
      print_status('  mme_findings             - Show collected findings')
      print_status('  mme_stop                 - Stop current run')
      print_status('  mme_checkpoints          - List paused engine states')
      print_status('  mme_sessions             - List MSF sessions gained via MME')
      print_status('  mme_resume <id>          - Resume a paused session')
      print_status('  mme_scope                - Manage target scope')
      print_status('  mme_config               - Manage configuration')
      print_status('  mme_doctor               - Run environment health checks')
      print_status('  mme_export <format>      - Export findings (defectdojo)')
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
      %w[html json md markdown pdf]
    end

    private

    def export_to_defectdojo
      url = Config.get('defectdojo_url')
      token = Config.get('defectdojo_token')

      if url.to_s.empty? || token.to_s.empty?
        print_error('DefectDojo not configured. Set defectdojo_url and defectdojo_token via mme_config.')
        return
      end

      begin
        require 'net/http'
        require 'json'
        require 'uri'

        findings = @engine.findings
        if findings.empty?
          print_status('No findings to export.')
          return
        end

        # Map MME severities to DefectDojo severities
        severity_map = {
          'critical' => 'Critical', 'high' => 'High',
          'medium' => 'Medium', 'low' => 'Low',
          'informational' => 'Info'
        }

        exported = 0
        findings.each do |f|
          uri = URI.parse("#{url.chomp('/')}/findings/")
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == 'https'
          http.open_timeout = 10
          http.read_timeout = 30

          request = Net::HTTP::Post.new(uri.path)
          request['Authorization'] = "Token #{token}"
          request['Content-Type'] = 'application/json'
          request.body = JSON.generate({
            title: f.title,
            severity: severity_map[f.severity] || 'Info',
            description: f.description,
            impact: f.impact,
            mitigation: f.remediation,
            endpoints: ["#{f.host}:#{f.port}"],
            active: true,
            verified: f.status == 'confirmed',
            numerical_severity: Mme::Finding::SEVERITIES.index(f.severity) || 4
          })

          response = http.request(request)
          if response.code.to_i < 300
            exported += 1
          else
            print_warning("Failed to export finding '#{f.title}': HTTP #{response.code}")
          end
        end

        print_good("Exported #{exported}/#{findings.size} findings to DefectDojo")
      rescue LoadError
        print_error('net/http is required for DefectDojo export (should be part of Ruby stdlib)')
      rescue => e
        print_error("DefectDojo export error: #{e.message}")
      end
    end

    def get_engine
      @engine ||= Engine.new(framework, driver.output)
    end
  end
end
