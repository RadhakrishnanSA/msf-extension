# frozen_string_literal: true

require 'yaml'
require 'fileutils'

module Mme
  # Configuration manager for MME
  class Config
    DEFAULT_CONFIG = {
      'threads' => 1,
      'profile' => 'normal',
      'brute' => false,
      'max_scan_duration' => 3600,
      'report_dir' => File.join(Dir.home, '.msf4', 'mme', 'reports'),
      'playbook_dirs' => [File.join(Dir.home, '.msf4', 'mme', 'playbooks')],
      'wordlist_paths' => ['/usr/share/seclists', '/usr/share/wordlists/seclists', '/usr/share/wordlists'],
      'blocklist_modules' => [],
      'redact_credentials' => true,
      'theme' => 'dark',
      'global_max_threads' => 10,
      'defectdojo_url' => '',
      'defectdojo_token' => '',
      'module_timeout' => 300
    }.freeze

    def self.config_file
      File.join(Dir.home, '.msf4', 'mme', 'config.yml')
    end

    def self.load
      unless File.exist?(config_file)
        save(DEFAULT_CONFIG.dup)
      end

      begin
        data = YAML.safe_load(File.read(config_file)) || {}
        @config = DEFAULT_CONFIG.merge(data)
      rescue StandardError => e
        warn("[-] Failed to load MME config: #{e.message}")
        @config = DEFAULT_CONFIG.dup
      end

      @config
    end

    def self.save(data)
      FileUtils.mkdir_p(File.dirname(config_file))
      File.write(config_file, data.to_yaml)
      @config = data
    end

    def self.get(key)
      load unless @config
      @config[key.to_s]
    end

    def self.set(key, value)
      load unless @config

      # Type conversion based on default type
      default_val = DEFAULT_CONFIG[key.to_s]
      case default_val
      when Integer
        value = value.to_i
      when TrueClass, FalseClass
        value = (value.to_s.downcase == 'true' || value.to_s.downcase == 'yes' || value == '1' || value.to_s.downcase == 'y')
      when Array
        value = value.split(',').map(&:strip) if value.is_a?(String)
      end

      @config[key.to_s] = value
      save(@config)
    end

    def self.all
      load unless @config
      @config.dup
    end
  end
end
