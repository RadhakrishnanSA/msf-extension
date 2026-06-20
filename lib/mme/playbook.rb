require 'yaml'

module Mme
  class PlaybookStep
    attr_accessor :name, :module_path, :options, :always_run, :evidence_config

    def initialize(attrs = {})
      @name = attrs['name'] || attrs[:name] || 'Unnamed Step'
      @module_path = attrs['module'] || attrs[:module_path] || ''
      @options = attrs['options'] || attrs[:options] || {}
      @always_run = attrs.fetch('always_run', attrs.fetch(:always_run, true))
      @evidence_config = attrs['evidence'] || attrs[:evidence_config] || {}
    end

    def to_s
      "#{name} (#{module_path})"
    end
  end

  class Playbook
    attr_accessor :service, :ports, :description, :author, :version, :steps, :file_path

    def initialize(attrs = {})
      @service = attrs['service'] || attrs[:service] || ''
      @ports = attrs['ports'] || attrs[:ports] || []
      @description = attrs['description'] || attrs[:description] || ''
      @author = attrs['author'] || attrs[:author] || 'MME'
      @version = attrs['version'] || attrs[:version] || '1.0'
      @steps = []
      @file_path = attrs[:file_path] || ''

      raw_steps = attrs['steps'] || attrs[:steps] || []
      raw_steps.each do |step_data|
        @steps << PlaybookStep.new(step_data)
      end
    end

    def self.load_from_file(path)
      data = YAML.safe_load(File.read(path), permitted_classes: [Symbol])
      pb = new(data)
      pb.file_path = path
      pb
    rescue => e
      raise "Failed to load playbook #{path}: #{e.message}"
    end

    def matches_service?(service_name, port = nil)
      return true if service.to_s.downcase == service_name.to_s.downcase
      return true if port && ports.include?(port.to_i)
      # Handle service name aliases
      aliases = {
        'http' => %w[http http-alt http-proxy www],
        'https' => %w[https ssl/http ssl/https],
        'smb' => %w[smb microsoft-ds netbios-ssn],
        'mssql' => %w[mssql ms-sql-s ms-sql-m],
        'postgresql' => %w[postgresql postgres],
        'netbios-ssn' => %w[netbios-ssn smb]
      }
      (aliases[service.to_s.downcase] || []).include?(service_name.to_s.downcase)
    end

    def step_count
      steps.size
    end

    def to_s
      "Playbook[#{service}] - #{description} (#{steps.size} steps)"
    end
  end
end
