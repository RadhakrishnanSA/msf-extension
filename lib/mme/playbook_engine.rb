module Mme
  # Result of a complete playbook execution
  PlaybookResult = Struct.new(
    :playbook, :service_entry, :step_results,
    :findings_count, :success, :timestamp, :duration,
    keyword_init: true
  )

  class PlaybookEngine
    attr_reader :playbooks

    def initialize(framework, console_output = nil)
      @framework = framework
      @console_output = console_output
      @module_runner = ModuleRunner.new(framework, console_output)
      @playbooks = {}
    end

    # Load all playbook YAML files from a directory
    def load_playbooks(directory)
      unless File.directory?(directory)
        log_error("Playbook directory not found: #{directory}")
        return
      end

      Dir.glob(File.join(directory, '*.yml')).each do |file|
        begin
          pb = Playbook.load_from_file(file)
          @playbooks[pb.service.downcase] = pb
          log_status("Loaded playbook: #{pb.service} (#{pb.step_count} steps)")
        rescue => e
          log_error("Failed to load playbook #{file}: #{e.message}")
        end
      end

      log_good("Loaded #{@playbooks.size} playbooks")
    end

    # Find a matching playbook for a service
    def find_playbook(service_name, port = nil)
      # Direct match first
      pb = @playbooks[service_name.to_s.downcase]
      return pb if pb

      # Try matching by port or alias
      @playbooks.values.find { |p| p.matches_service?(service_name, port) }
    end

    # Execute a playbook against a service
    def execute(playbook, service_entry, evidence_collector, opts = {})
      start_time = Time.now
      step_results = []
      findings_count = 0
      profile = opts[:profile] || :normal
      no_brute = opts[:no_brute] || false

      log_status("Executing playbook: #{playbook.service} against #{service_entry}")
      log_status("Steps to execute: #{playbook.step_count}")

      playbook.steps.each_with_index do |step, idx|
        if no_brute && (step.module_path.include?('login') || step.module_path.include?('brute'))
          log_warning("  [!] Skipping brute-force module due to --no-brute flag: #{step.name}")
          next
        end

        if profile == :stealth && idx > 0
          delay = rand(2..5)
          log_status("  [Stealth] Delaying execution by #{delay}s...")
          sleep(delay)
        end
        
        log_status("  Step [#{idx + 1}/#{playbook.step_count}]: #{step.name}")

        # Build module options
        options = build_options(step, service_entry)

        # Run the module
        result = @module_runner.run(step.module_path, options)
        step_results << result

        # Collect evidence if module produced output
        if result.success
          evidence = evidence_collector.collect(result, service_entry, step)
          findings_count += 1 if evidence&.finding_id
        else
          log_warning("  Step failed: #{step.name} - #{result.error}")
        end
      end

      duration = Time.now - start_time
      success = step_results.any?(&:success)

      log_good("Playbook #{playbook.service} completed in #{duration.round(1)}s - #{findings_count} findings")

      PlaybookResult.new(
        playbook: playbook,
        service_entry: service_entry,
        step_results: step_results,
        findings_count: findings_count,
        success: success,
        timestamp: start_time,
        duration: duration
      )
    end

    def list_playbooks
      @playbooks.values.sort_by(&:service)
    end

    def playbook_count
      @playbooks.size
    end

    private

    # Build module datastore options from step config and service entry
    def build_options(step, service_entry)
      opts = {
        'RHOSTS' => service_entry.host,
        'RPORT'  => service_entry.port.to_s,
        'THREADS' => '1'
      }

      # Add SSL for HTTPS
      if service_entry.name.to_s.downcase.include?('https') || service_entry.port.to_i == 443
        opts['SSL'] = 'true'
      end

      # Smart Wordlist Injection for Login Modules
      if step.module_path.include?('login') || step.module_path.include?('brute')
        inject_smart_wordlists(opts, service_entry.name.to_s.downcase)
      end

      # Merge step-specific options (from YAML)
      step.options.each do |key, value|
        opts[key.to_s] = value.to_s
      end

      opts
    end

    def inject_smart_wordlists(opts, service_name)
      # Check standard seclist locations
      seclists_paths = [
        '/usr/share/seclists',
        '/usr/share/wordlists/seclists'
      ]
      base_path = seclists_paths.find { |p| File.directory?(p) }
      
      # 1. Passwords (Default to rockyou if available)
      rockyou = '/usr/share/wordlists/rockyou.txt'
      if File.exist?(rockyou)
        opts['PASS_FILE'] = rockyou
      else
        # Fallback to MSF default
        opts['PASS_FILE'] = ::Msf::Config.install_root + '/data/wordlists/unix_passwords.txt'
      end

      # 2. Usernames (Service specific if seclists exists)
      if base_path
        service_user_file = File.join(base_path, 'Passwords', 'Default-Credentials', "#{service_name}-betterdefaultpasslist.txt")
        if File.exist?(service_user_file)
          opts['USERPASS_FILE'] = service_user_file
          opts.delete('PASS_FILE') # Avoid redundant pass file if we have a userpass combo
        else
          opts['USER_FILE'] = File.join(base_path, 'Usernames', 'top-usernames-shortlist.txt')
        end
      else
        # Fallback to MSF default
        opts['USER_FILE'] = ::Msf::Config.install_root + '/data/wordlists/unix_users.txt'
      end
    end

    def log_status(msg)
      if @console_output
        @console_output.print_status(msg)
      end
    end

    def log_good(msg)
      if @console_output
        @console_output.print_good(msg)
      end
    end

    def log_error(msg)
      if @console_output
        @console_output.print_error(msg)
      end
    end

    def log_warning(msg)
      if @console_output
        @console_output.print_warning(msg) if @console_output.respond_to?(:print_warning)
      end
    end
  end
end
