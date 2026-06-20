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
      brute = opts[:brute] || false

      log_status("Executing playbook: #{playbook.service} against #{service_entry}")
      log_status("Steps to execute: #{playbook.step_count}")

      # Map steps by index and ID for branching
      steps = playbook.steps
      step_by_id = steps.map { |s| [s.id, s] }.to_h
      
      current_step_idx = 0
      executed_count = 0

      while current_step_idx < steps.size
        step = steps[current_step_idx]
        executed_count += 1

        if !brute && (step.module_path.include?('login') || step.module_path.include?('brute'))
          log_warning("  [!] Skipping brute-force module (opt-in required via --brute): #{step.name}")
          current_step_idx += 1
          next
        end

        # Check conditions
        if step.condition
          unless evaluate_condition(step.condition, step_results, evidence_collector)
            log_status("  [-] Condition not met for step: #{step.name}. Skipping.")
            current_step_idx = determine_next_step_idx(step.on_failure, steps, step_by_id, current_step_idx + 1)
            next
          end
        end

        if profile == :stealth && executed_count > 1
          delay = rand(2..5)
          log_status("  [Stealth] Delaying execution by #{delay}s...")
          sleep(delay)
        end
        
        log_status("  Step [#{current_step_idx + 1}/#{playbook.step_count}]: #{step.name} (ID: #{step.id})")

        # Build module options
        options = build_options(step, service_entry)

        # Run the module
        result = @module_runner.run(step.module_path, options)
        step_results << result

        # Collect evidence if module produced output
        if result.executed
          evidence = evidence_collector.collect(result, service_entry, step)
          findings_count += 1 if evidence&.finding_id
          
          # Branching on success
          current_step_idx = determine_next_step_idx(step.on_success, steps, step_by_id, current_step_idx + 1)
        else
          log_warning("  Step failed: #{step.name} - #{result.error}")
          # Branching on failure
          current_step_idx = determine_next_step_idx(step.on_failure, steps, step_by_id, current_step_idx + 1)
        end
      end

      duration = Time.now - start_time
      success = step_results.any?(&:executed)

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

    def determine_next_step_idx(target_id, steps, step_by_id, default_next_idx)
      return default_next_idx if target_id.nil? || target_id.empty?
      
      # Find the index of the target step ID
      target_step = step_by_id[target_id]
      if target_step
        idx = steps.index(target_step)
        idx || default_next_idx
      else
        log_warning("  [!] Branch target ID not found: #{target_id}. Proceeding to next step.")
        default_next_idx
      end
    end

    # Condition evaluator. Expects format: "step_id =~ /regex/i" or "any =~ /regex/"
    def evaluate_condition(condition_str, step_results, evidence_collector)
      begin
        parts = condition_str.split(' ', 3)
        if parts.size == 3 && parts[1] == '=~'
          step_id = parts[0]
          
          # Extract regex pattern and ignore_case flag (e.g., /ubuntu/i -> ubuntu, i)
          regex_str = parts[2]
          ignore_case = false
          if regex_str.start_with?('/')
            last_slash = regex_str.rindex('/')
            if last_slash && last_slash > 0
              flags = regex_str[(last_slash + 1)..-1]
              ignore_case = flags.include?('i')
              regex_str = regex_str[1...last_slash]
            end
          end
          
          regex = Regexp.new(regex_str, ignore_case ? Regexp::IGNORECASE : 0)

          if step_id.downcase == 'any'
            output = step_results.map(&:output).join("\n")
            return !!output.match(regex)
          else
            # Find evidence specifically for this step ID
            evidence = evidence_collector.evidence_list.find { |e| e.step_id == step_id }
            if evidence
              return !!evidence.raw_output.to_s.match(regex)
            else
              log_warning("  [!] Condition step_id '#{step_id}' has no evidence to evaluate.")
              return false
            end
          end
        end
      rescue => e
        log_warning("Failed to evaluate condition '#{condition_str}': #{e.message}")
      end
      true # Default to run if parsing fails
    end

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
