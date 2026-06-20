require 'logger'
require 'fileutils'
require 'time'

module Mme
  class AuditLogger
    def self.instance
      @instance ||= new
    end

    def initialize
      log_dir = File.join(Dir.home, '.msf4', 'mme', 'logs')
      FileUtils.mkdir_p(log_dir) unless Dir.exist?(log_dir)
      
      log_file = File.join(log_dir, 'mme_audit.log')
      @logger = Logger.new(log_file, 'daily')
      @logger.formatter = proc do |severity, datetime, progname, msg|
        "#{datetime.iso8601} [#{severity}] #{msg}\n"
      end
    end

    def log(level, message, metadata = {})
      meta_str = metadata.empty? ? "" : " | #{metadata.map { |k, v| "#{k}=#{v}" }.join(' ')}"
      @logger.send(level, "#{message}#{meta_str}")
    end

    def info(message, metadata = {})
      log(:info, message, metadata)
    end

    def error(message, metadata = {})
      log(:error, message, metadata)
    end

    def warn(message, metadata = {})
      log(:warn, message, metadata)
    end

    def debug(message, metadata = {})
      log(:debug, message, metadata)
    end
  end
end
