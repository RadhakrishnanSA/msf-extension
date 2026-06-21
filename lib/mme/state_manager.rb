# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'

module Mme
  # Manages the state of MME sessions.
  class StateManager
    attr_reader :session_id, :target, :start_time, :options

    def initialize(session_id = nil)
      # SECURITY: session_id is always a SecureRandom.uuid (hex + dashes only),
      # safe for use in file paths with no risk of path traversal.
      @session_id = session_id || SecureRandom.uuid
      @target = nil
      @start_time = nil
      @options = {}
    end

    def self.state_dir
      dir = File.join(Dir.home, '.msf4', 'mme', 'state')
      FileUtils.mkdir_p(dir) unless Dir.exist?(dir)
      dir
    end

    def self.list_sessions
      sessions = []
      Dir.glob(File.join(state_dir, '*.json')).each do |file|
        begin
          data = JSON.parse(File.read(file))
          sessions << {
            id: File.basename(file, '.json'),
            target: data['target'],
            start_time: data['start_time'],
            queue_total: data['queue']&.size || 0,
            queue_completed: data['queue']&.count { |s| %w[completed failed skipped].include?(s['status']) } || 0,
            last_updated: File.mtime(file)
          }
        rescue StandardError
          next
        end
      end
      sessions.sort_by { |s| s[:last_updated] }.reverse
    end

    def state_file
      File.join(self.class.state_dir, "#{@session_id}.json")
    end

    def save(target, start_time, options, service_queue)
      @target = target
      @start_time = start_time
      @options = options

      data = {
        session_id: @session_id,
        target: target,
        start_time: start_time,
        options: options,
        queue: service_queue.entries.map do |e|
          {
            host: e.host,
            port: e.port,
            proto: e.proto,
            name: e.name,
            info: e.info,
            status: e.status.to_s
          }
        end
      }

      File.write(state_file, JSON.pretty_generate(data))
    end

    def load
      return nil unless File.exist?(state_file)

      data = JSON.parse(File.read(state_file))
      @target = data['target']
      @start_time = data['start_time'] ? Time.parse(data['start_time']) : Time.now
      @options = data['options'] || {}

      # Reconstruct the service queue
      queue = ServiceQueue.new
      (data['queue'] || []).each do |q|
        entry = ServiceEntry.new(
          host: q['host'],
          port: q['port'],
          proto: q['proto'],
          name: q['name'],
          info: q['info'],
          status: q['status'].to_sym
        )
        # Directly add to entries to bypass duplication checks and state resets
        queue.entries << entry
      end

      queue
    end

    def delete
      File.delete(state_file) if File.exist?(state_file)
    end
  end
end
