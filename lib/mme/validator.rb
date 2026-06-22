# frozen_string_literal: true

require_relative 'config'

module Mme
  # Input validation utilities
  module Validator
    TARGET_PATTERN = %r{\A[a-zA-Z0-9.\-_/,:?=&]+\z}.freeze
    VALID_PROFILES = %i[normal stealth].freeze
    VALID_REPORT_FORMATS = %w[html json md markdown pdf].freeze

    # Exception raised for validation errors.
    class ValidationError < StandardError; end

    def self.validate_target!(target)
      raise ValidationError, 'Target cannot be empty' if target.nil? || target.strip.empty?
      unless target.match?(TARGET_PATTERN)
        raise ValidationError,
              "Invalid characters in target: #{target}. Only alphanumeric, dots, hyphens, " \
              'underscores, slashes, commas, colons, ampersands, equals, and question marks are allowed.'
      end
      raise ValidationError, "Target is too long (max 253 characters): #{target}" if target.length > 253

      true
    end

    def self.validate_file_path!(path, must_exist: true)
      raise ValidationError, 'File path cannot be empty' if path.nil? || path.strip.empty?
      raise ValidationError, "Path contains directory traversal: #{path}" if path.include?('..')
      raise ValidationError, "File not found: #{path}" if must_exist && !File.exist?(path)
      raise ValidationError, "File not readable: #{path}" if must_exist && !File.readable?(path)

      true
    end

    def self.validate_threads!(count)
      count = count.to_i
      raise ValidationError, "Thread count must be a positive integer, got: #{count}" if count < 1

      max = Config.get('global_max_threads') || 10
      raise ValidationError, "Thread count #{count} exceeds maximum allowed (#{max})" if count > max

      count
    end

    def self.validate_profile!(profile)
      sym = profile.to_s.downcase.to_sym
      raise ValidationError, "Unknown profile: #{profile}. Valid profiles: #{VALID_PROFILES.join(', ')}" unless VALID_PROFILES.include?(sym)

      sym
    end

    def self.validate_report_format!(format)
      fmt = format.to_s.downcase
      unless VALID_REPORT_FORMATS.include?(fmt)
        raise ValidationError,
              "Unknown report format: #{format}. Valid formats: #{VALID_REPORT_FORMATS.join(', ')}"
      end

      fmt
    end

    def self.validate_session_id!(id)
      raise ValidationError, 'Session ID cannot be empty' if id.nil? || id.strip.empty?
      raise ValidationError, "Invalid session ID format: #{id}" unless id.match?(/\A[a-f0-9-]+\z/i)

      true
    end
  end
end
