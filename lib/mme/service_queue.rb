# frozen_string_literal: true


# MME namespace
module Mme
  # Struct for service entry
  ServiceEntry = Struct.new(:host, :port, :proto, :name, :info, :status, keyword_init: true) do
    def to_s
      "#{name || 'unknown'}://#{host}:#{port}"
    end

    def service_key
      "#{host}:#{port}"
    end
  end

  # Queue for managing services
  class ServiceQueue
    # Port-to-service name fallback mapping
    PORT_SERVICE_MAP = {
      21 => 'ftp', 22 => 'ssh', 23 => 'telnet', 25 => 'smtp',
      53 => 'dns', 80 => 'http', 110 => 'pop3', 111 => 'rpcbind',
      135 => 'msrpc', 139 => 'netbios-ssn', 143 => 'imap',
      443 => 'https', 445 => 'smb', 993 => 'imaps', 995 => 'pop3s',
      1433 => 'mssql', 1521 => 'oracle', 3306 => 'mysql',
      3389 => 'rdp', 5432 => 'postgresql', 5900 => 'vnc',
      6379 => 'redis', 8080 => 'http', 8443 => 'https',
      27_017 => 'mongodb', 161 => 'snmp', 162 => 'snmp'
    }.freeze

    attr_reader :entries

    def initialize
      @entries = []
      @mutex = Mutex.new
    end

    def add(service_entry)
      @mutex.synchronize do
        service_entry.status = :pending
        # Normalize service name from port if missing
        service_entry.name = PORT_SERVICE_MAP[service_entry.port.to_i] || 'unknown' if service_entry.name.nil? || service_entry.name.empty?
        @entries << service_entry unless @entries.any? { |e| e.service_key == service_entry.service_key }
      end
    end

    def add_from_msf_service(msf_service)
      entry = ServiceEntry.new(
        host: msf_service.host.address,
        port: msf_service.port,
        proto: msf_service.proto,
        name: msf_service.name,
        info: msf_service.info,
        status: :pending
      )
      add(entry)
      entry
    end

    def next_service
      @mutex.synchronize do
        entry = @entries.find { |e| e.status == :pending }
        entry&.status = :in_progress
        entry
      end
    end

    def complete(service_entry)
      @mutex.synchronize { service_entry.status = :completed }
    end

    def skip(service_entry)
      @mutex.synchronize { service_entry.status = :skipped }
    end

    def fail(service_entry)
      @mutex.synchronize { service_entry.status = :failed }
    end

    def progress
      @mutex.synchronize do
        {
          total: @entries.size,
          completed: @entries.count { |e| e.status == :completed },
          pending: @entries.count { |e| e.status == :pending },
          in_progress: @entries.count { |e| e.status == :in_progress },
          failed: @entries.count { |e| e.status == :failed },
          skipped: @entries.count { |e| e.status == :skipped }
        }
      end
    end

    def empty?
      @mutex.synchronize { @entries.none? { |e| e.status == :pending } }
    end

    def size
      @entries.size
    end

    def each(&block)
      @entries.each(&block)
    end

    def reset
      @mutex.synchronize { @entries.each { |e| e.status = :pending } }
    end

    def hosts
      @entries.map(&:host).uniq
    end

    def services_for_host(host)
      @entries.select { |e| e.host == host }
    end

    def progress_bar
      p = progress
      done = p[:completed] + p[:skipped] + p[:failed]
      total = p[:total]
      pct = total.positive? ? (done * 100.0 / total).round(1) : 0
      filled = (pct / 5).to_i
      bar = ('#' * filled) + ('-' * (20 - filled))
      "[#{bar}] #{pct}% (#{done}/#{total})"
    end

    def to_s
      lines = ["Service Queue: #{progress_bar}"]
      @entries.group_by(&:host).each do |host, svcs|
        lines << "  Host: #{host}"
        svcs.each do |svc|
          status_icon = case svc.status
                        when :completed then '[✓]'
                        when :in_progress then '[►]'
                        when :failed then '[✗]'
                        when :skipped then '[—]'
                        else '[ ]'
                        end
          lines << "    #{status_icon} #{svc.port}/#{svc.proto} #{svc.name} #{svc.info}"
        end
      end
      lines.join("\n")
    end
  end
end
