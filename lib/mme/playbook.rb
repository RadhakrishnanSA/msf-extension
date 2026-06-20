require 'yaml'

module Mme
  class PlaybookStep
    attr_accessor :id, :name, :module_path, :options, :always_run, :evidence_config,
                  :condition, :on_success, :on_failure

    def initialize(attrs = {})
      @id = attrs['id'] || attrs[:id] || "step_#{SecureRandom.hex(4)}"
      @name = attrs['name'] || attrs[:name] || 'Unnamed Step'
      @module_path = attrs['module'] || attrs[:module_path] || ''
      @options = attrs['options'] || attrs[:options] || {}
      @always_run = attrs.fetch('always_run', attrs.fetch(:always_run, true))
      @evidence_config = attrs['evidence'] || attrs[:evidence_config] || {}
      @condition = attrs['condition'] || attrs[:condition]
      @on_success = attrs['on_success'] || attrs[:on_success]
      @on_failure = attrs['on_failure'] || attrs[:on_failure]
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
      errors = validate_data!(data, path)
      unless errors.empty?
        raise "Playbook validation failed:\n  #{errors.join("\n  ")}"
      end
      pb = new(data)
      pb.file_path = path
      pb
    rescue YAML::SyntaxError => e
      raise "Playbook YAML syntax error in #{path}: #{e.message}"
    rescue => e
      raise "Failed to load playbook #{path}: #{e.message}"
    end

    def self.validate_data!(data, path)
      errors = []
      errors << "#{path}: Top-level must be a Hash, got #{data.class}" unless data.is_a?(Hash)
      return errors unless data.is_a?(Hash)

      errors << "#{path}: Missing required field 'service'" unless data['service'].is_a?(String) && !data['service'].empty?
      errors << "#{path}: 'ports' must be an Array" if data.key?('ports') && !data['ports'].is_a?(Array)
      errors << "#{path}: Missing or empty 'steps' array" unless data['steps'].is_a?(Array) && !data['steps'].empty?

      if data['steps'].is_a?(Array)
        data['steps'].each_with_index do |step, idx|
          prefix = "#{path}: steps[#{idx}]"
          errors << "#{prefix}: must be a Hash" unless step.is_a?(Hash)
          next unless step.is_a?(Hash)
          errors << "#{prefix}: missing 'name'" unless step['name'].is_a?(String) && !step['name'].empty?
          errors << "#{prefix}: missing 'module'" unless step['module'].is_a?(String) && !step['module'].empty?
          if step['condition']
            unless step['condition'].is_a?(String) && step['condition'].match?(/\A\S+\s+=~\s+\/.+\/i?\z/)
              errors << "#{prefix}: 'condition' must be in format 'step_id =~ /regex/' or 'any =~ /regex/i'"
            end
          end
          %w[on_success on_failure].each do |field|
            if step[field] && !(step[field].is_a?(String) && !step[field].empty?)
              errors << "#{prefix}: '#{field}' must be a non-empty string (step ID)"
            end
          end
          if step['options'] && !step['options'].is_a?(Hash)
            errors << "#{prefix}: 'options' must be a Hash"
          end
          if step['evidence'] && !step['evidence'].is_a?(Hash)
            errors << "#{prefix}: 'evidence' must be a Hash"
          end
        end
      end

      errors
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
