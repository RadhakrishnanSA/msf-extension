# frozen_string_literal: true

require 'uri'
require 'resolv'
require 'net/http'
require 'json'
require 'open3'
require 'fileutils'
require 'set'

module Mme
  class TargetResolver
    # Result of the resolution phase
    ResolutionResult = Struct.new(
      :original_target,
      :target_type,
      :resolved_hosts,    # Array of { ip: '1.2.3.4', hostname: 'foo.com' }
      :excluded_hosts,    # Array of IPs excluded by scope
      :dead_hosts,        # Array of IPs that failed ping sweep
      :subdomains_found,  # Number of subdomains discovered
      keyword_init: true
    )

    def initialize(framework, console_output = nil)
      @framework = framework
      @console_output = console_output
    end

    def resolve!(target, opts = {})
      start_time = Time.now
      log_status('[Phase 0/6] Target Resolution and Discovery')
      
      result = ResolutionResult.new(
        original_target: target,
        resolved_hosts: [],
        excluded_hosts: [],
        dead_hosts: [],
        subdomains_found: 0
      )

      # 1. Classification & URL Stripping
      target, result.target_type = classify_target(target)
      log_status("  [*] Target classified as: #{result.target_type}")

      scope = Scope.new(@framework.db.workspace.name)

      # 2. Branch based on classification
      case result.target_type
      when :ip
        process_single_ip(target, scope, result)
      when :range
        process_range(target, scope, result, opts)
      when :domain
        process_domain(target, scope, result, opts)
      end

      # Final scope warning
      if scope.empty? && result.resolved_hosts.any?
        log_warning("  [!] No scope defined! All #{result.resolved_hosts.size} discovered targets will be queued.")
      else
        log_good("  [+] Resolution complete. Queuing #{result.resolved_hosts.size} live/in-scope hosts.")
        if result.excluded_hosts.any?
          log_warning("  [-] Excluded #{result.excluded_hosts.size} out-of-scope targets.")
        end
        if result.dead_hosts.any?
          log_status("  [-] Ignored #{result.dead_hosts.size} unresponsive hosts.")
        end
      end

      result
    end

    private

    def classify_target(target)
      target = target.strip

      # Check URL first
      if target.start_with?('http://', 'https://')
        begin
          uri = URI.parse(target)
          target = uri.host if uri.host
        rescue URI::InvalidURIError
          # Fall through
        end
      end

      # Basic IP regex
      if target.match?(/\A(\d{1,3}\.){3}\d{1,3}\z/)
        [target, :ip]
      # Basic CIDR or hyphen range regex
      elsif target.match?(/\A(\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2}|-\d{1,3})\z/)
        [target, :range]
      else
        [target, :domain]
      end
    end

    def process_single_ip(ip, scope, result)
      if scope.empty? || scope.include?(ip)
        result.resolved_hosts << { ip: ip, hostname: nil }
      else
        result.excluded_hosts << ip
      end
    end

    def process_range(range, scope, result, opts)
      if opts[:no_pingsweep]
        log_status('  [*] Skipping ping sweep (--no-pingsweep). Using raw range.')
        log_warning('  [!] Scope checks are deferred to Nmap for raw ranges without ping sweep.')
        result.resolved_hosts << { ip: range, hostname: nil }
        return
      end

      live_ips = run_ping_sweep(range)
      filter_by_scope(live_ips, scope, result)
    end

    def run_ping_sweep(range)
      log_status("  [*] Running ICMP/ARP ping sweep against #{range}...")
      
      output_dir = File.join(Dir.home, '.msf4', 'mme', 'scans')
      FileUtils.mkdir_p(output_dir)
      temp_xml = File.join(output_dir, "ping_sweep_#{Time.now.to_i}.xml")
      
      nmap_args = ['-sn', '-T4', '-oX', temp_xml, range]
      
      begin
        stdout, status = Open3.capture2e('nmap', *nmap_args)
        
        unless status.success?
          log_error("  [-] Ping sweep failed: #{stdout}")
          return []
        end

        live_ips = extract_live_ips_from_xml(temp_xml)
        log_status("  [+] Ping sweep discovered #{live_ips.size} live hosts.")
        live_ips
      ensure
        File.delete(temp_xml) if File.exist?(temp_xml)
      end
    end

    def filter_by_scope(ips, scope, result)
      ips.each do |ip|
        if scope.empty? || scope.include?(ip)
          result.resolved_hosts << { ip: ip, hostname: nil }
        else
          result.excluded_hosts << ip
        end
      end
    end

    def process_domain(domain, scope, result, opts)
      if opts[:no_subdomain_enum]
        log_status("  [*] Skipping subdomain enum (--no-subdomain-enum).")
        subdomains = [domain]
      else
        log_status("  [*] Enumerating subdomains for #{domain}...")
        subdomains = enumerate_subdomains(domain, opts)
        result.subdomains_found = subdomains.size
        log_good("  [+] Discovered #{subdomains.size} unique subdomains.")
      end

      resolved_map = resolve_names_to_ips(subdomains, opts)
      apply_scope_filter(resolved_map, scope, result)
    end

    def resolve_names_to_ips(subdomains, opts)
      log_status("  [*] Resolving #{subdomains.size} names to IPs...")
      resolved_map = {}
      
      threads = []
      max_threads = [(opts[:threads] || 10), 20].min

      queue = Queue.new
      subdomains.each { |s| queue << s }
      mutex = Mutex.new

      max_threads.times do
        threads << Thread.new do
          loop do
            begin
              name = queue.pop(true)
            rescue ThreadError
              break
            end
            begin
              ips = Resolv.getaddresses(name)
              mutex.synchronize do
                ips.each do |ip|
                  resolved_map[ip] ||= []
                  resolved_map[ip] << name unless resolved_map[ip].include?(name)
                end
              end
            rescue Resolv::ResolvError
              # Unresolvable
            end
          end
        end
      end
      threads.each(&:join)

      log_status("  [*] Names resolved to #{resolved_map.keys.size} unique IPs.")
      resolved_map
    end

    def apply_scope_filter(resolved_map, scope, result)
      resolved_map.each do |ip, names|
        if scope.empty? || scope.include?(ip)
          names.each { |name| result.resolved_hosts << { ip: ip, hostname: name } }
          result.resolved_hosts << { ip: ip, hostname: nil } unless result.resolved_hosts.any? { |h| h[:ip] == ip && h[:hostname].nil? }
        else
          result.excluded_hosts << ip
        end
      end
    end

    def enumerate_subdomains(domain, opts)
      subdomains = Set.new([domain])
      enumerate_passive(domain, subdomains)
      
      unless opts[:passive_only]
        enumerate_active_tools(domain, subdomains)
        enumerate_dns_brute(domain, subdomains, opts)
      end

      subdomains.to_a
    end

    def enumerate_passive(domain, subdomains)
      log_status("    - Querying crt.sh (Passive)...")
      begin
        uri = URI("https://crt.sh/?q=%25.#{domain}&output=json")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 10
        http.read_timeout = 20
        
        req = Net::HTTP::Get.new(uri)
        res = http.request(req)
        
        if res.code == '200'
          data = JSON.parse(res.body)
          data.each do |entry|
            name = entry['name_value'].to_s.downcase
            name.split("\n").each do |n|
              n = n.sub(/^\*\./, '')
              subdomains << n if n.end_with?(domain)
            end
          end
        end
      rescue StandardError => e
        log_warning("      [!] crt.sh query failed: #{e.message}")
      end
    end

    def enumerate_active_tools(domain, subdomains)
      if tool_installed?('subfinder')
        log_status("    - Running subfinder...")
        out, stat = Open3.capture2e('subfinder', '-d', domain, '-silent')
        if stat.success?
          out.lines.each { |l| subdomains << l.strip.downcase }
        end
      elsif tool_installed?('amass')
        log_status("    - Running amass enum...")
        out, stat = Open3.capture2e('amass', 'enum', '-passive', '-d', domain)
        if stat.success?
          out.lines.each { |l| subdomains << l.strip.downcase }
        end
      end
    end

    def enumerate_dns_brute(domain, subdomains, opts)
      log_status("    - Brute-forcing DNS (Active)...")
      wordlist = opts[:subdomain_wordlist] || default_subdomain_wordlist
      if wordlist && File.exist?(wordlist)
        File.readlines(wordlist).each do |word|
          word = word.strip.downcase
          next if word.empty? || word.start_with?('#')
          subdomains << "#{word}.#{domain}"
        end
      else
        log_warning("      [!] No subdomain wordlist found. Skipping active brute.")
      end
    end

    def extract_live_ips_from_xml(xml_path)
      return [] unless File.exist?(xml_path)
      content = File.read(xml_path)
      ips = []
      
      # Nmap XML format for hosts:
      # <host><status state="up" reason="arp-response" reason_ttl="0"/>
      # <address addr="10.0.0.5" addrtype="ipv4"/>
      # We extract the address if the state is "up" within the same <host> block.
      
      content.scan(/<host>(.*?)<\/host>/m).each do |host_block|
        block = host_block[0]
        if block.include?('status state="up"')
          if match = block.match(/<address addr="([^"]+)"/)
            ips << match[1]
          end
        end
      end
      
      ips.uniq
    end

    def tool_installed?(name)
      system("#{name} --version > /dev/null 2>&1") || system("#{name} --version > NUL 2>&1")
    rescue StandardError
      false
    end

    def default_subdomain_wordlist
      paths = [
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
        '/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt',
        '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
      ]
      paths.find { |p| File.exist?(p) }
    end

    def log_status(msg)
      @console_output ? @console_output.print_status(msg) : $stdout.puts("[*] #{msg}")
    end

    def log_good(msg)
      @console_output ? @console_output.print_good(msg) : $stdout.puts("[+] #{msg}")
    end

    def log_warning(msg)
      @console_output ? @console_output.print_warning(msg) : warn("[!] #{msg}")
    end

    def log_error(msg)
      @console_output ? @console_output.print_error(msg) : warn("[-] #{msg}")
    end
  end
end
