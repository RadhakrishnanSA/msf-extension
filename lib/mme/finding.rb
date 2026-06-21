# frozen_string_literal: true

require 'securerandom'

# MME namespace
module Mme
  # Finding representation
  class Finding
    include Comparable

    SEVERITIES = %w[critical high medium low informational].freeze
    STATUSES = %w[confirmed potential informational].freeze

    attr_accessor :id, :title, :severity, :description, :evidence,
                  :impact, :remediation, :references, :host, :port,
                  :service, :module_path, :timestamp, :status, :exploits

    def initialize(attrs = {})
      @id = attrs[:id] || SecureRandom.uuid
      @title = attrs[:title] || 'Untitled Finding'
      @severity = attrs[:severity] || 'informational'
      @description = attrs[:description] || ''
      @evidence = attrs[:evidence] || []
      @impact = attrs[:impact] || ''
      @remediation = attrs[:remediation] || ''
      @references = attrs[:references] || []
      @host = attrs[:host] || ''
      @port = attrs[:port]
      @service = attrs[:service] || ''
      @module_path = attrs[:module_path] || ''
      @timestamp = attrs[:timestamp] || Time.now
      @status = attrs[:status] || 'confirmed'
      @exploits = attrs[:exploits] || []
    end

    def severity_index
      SEVERITIES.index(severity.to_s.downcase) || 4
    end

    def severity_color
      case severity.to_s.downcase
      when 'critical' then "\e[31m"  # red
      when 'high'     then "\e[91m"  # light red
      when 'medium'   then "\e[33m"  # yellow
      when 'low'      then "\e[36m"  # cyan
      else "\e[37m" # white
      end
    end

    def to_h
      {
        id: @id, title: @title, severity: @severity,
        description: @description, evidence: @evidence,
        impact: @impact, remediation: @remediation,
        references: @references, host: @host, port: @port,
        service: @service, module_path: @module_path,
        timestamp: @timestamp.to_s, status: @status, exploits: @exploits
      }
    end

    def to_s
      "[#{severity.upcase}] #{title} - #{host}:#{port} (#{service})"
    end

    # Sort by severity (critical first)
    def <=>(other)
      severity_index <=> other.severity_index
    end
  end
end
