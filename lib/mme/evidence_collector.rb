require 'securerandom'

module Mme
  # Represents a piece of evidence from a module run
  Evidence = Struct.new(
    :id, :host, :port, :service, :module_path,
    :evidence_type, :content, :raw_output,
    :timestamp, :finding_id,
    keyword_init: true
  )

  class EvidenceCollector
    attr_reader :evidence_store, :findings_store

    def initialize(framework)
      @framework = framework
      @evidence_store = []
      @findings_store = []
      @mutex = Mutex.new
    end

    # Collect evidence from a module result
    # @param module_result [ModuleResult] result from ModuleRunner
    # @param service_entry [ServiceEntry] the service being scanned
    # @param step [PlaybookStep] the playbook step that generated this
    # @return [Evidence, nil]
    def collect(module_result, service_entry, step)
      return nil unless module_result&.success && !module_result.output.to_s.strip.empty?

      evidence = Evidence.new(
        id: SecureRandom.uuid,
        host: service_entry.host,
        port: service_entry.port,
        service: service_entry.name,
        module_path: module_result.module_path,
        evidence_type: step.evidence_config['type'] || 'general',
        content: extract_meaningful_content(module_result.output),
        raw_output: module_result.output,
        timestamp: Time.now,
        finding_id: nil
      )

      @mutex.synchronize { @evidence_store << evidence }

      # Create a finding if evidence config suggests it
      if has_meaningful_output?(module_result.output)
        finding = create_finding(evidence, step)
        evidence.finding_id = finding.id if finding
      end

      evidence
    end

    # Create a finding from evidence and step configuration
    def create_finding(evidence, step)
      config = step.evidence_config
      return nil if config.empty?

      finding = Finding.new(
        title: config['title'] || "#{step.name} - #{evidence.service}",
        severity: config['severity'] || 'informational',
        description: config['description'] || "Finding from #{step.name}",
        evidence: [evidence.raw_output],
        impact: config['impact'] || '',
        remediation: config['remediation'] || '',
        references: config['references'] || [],
        host: evidence.host,
        port: evidence.port,
        service: evidence.service,
        module_path: evidence.module_path,
        status: determine_status(evidence)
      )

      @mutex.synchronize { @findings_store << finding }

      # Store to MSF database if available
      store_finding_to_db(finding, evidence)

      finding
    end

    def findings
      @mutex.synchronize { @findings_store.dup }
    end

    def evidence_list
      @mutex.synchronize { @evidence_store.dup }
    end

    def findings_by_severity
      findings.group_by(&:severity).transform_values(&:count)
    end

    def findings_for_host(host)
      findings.select { |f| f.host == host }
    end

    # Store all findings to MSF database
    def store_to_db
      return unless @framework.db.active

      findings.each do |finding|
        store_finding_to_db(finding, nil)
      end
    end

    def summary
      {
        total_evidence: @evidence_store.size,
        total_findings: @findings_store.size,
        by_severity: findings_by_severity,
        hosts_with_findings: findings.map(&:host).uniq.size
      }
    end

    def clear
      @mutex.synchronize do
        @evidence_store.clear
        @findings_store.clear
      end
    end

    private

    def extract_meaningful_content(output)
      return '' if output.nil?
      lines = output.to_s.lines.reject { |l| l.strip.empty? || l.strip.start_with?('[*]') }
      lines.map(&:strip).join("\n")
    end

    def has_meaningful_output?(output)
      return false if output.nil? || output.strip.empty?
      # Check for positive result indicators
      positive_indicators = ['[+]', 'found', 'detected', 'version', 'running',
                             'allowed', 'enabled', 'anonymous', 'vulnerable',
                             'open', 'accessible']
      output_lower = output.downcase
      positive_indicators.any? { |indicator| output_lower.include?(indicator) }
    end

    def determine_status(evidence)
      output = evidence.raw_output.to_s.downcase
      if output.include?('vulnerable') || output.include?('anonymous') || output.include?('allowed')
        'confirmed'
      elsif output.include?('version') || output.include?('detected')
        'informational'
      else
        'potential'
      end
    end

    def store_finding_to_db(finding, evidence)
      return unless @framework.db.active

      begin
        # Store as a note
        @framework.db.report_note(
          host: finding.host,
          port: finding.port,
          type: "mme.finding.#{finding.severity}",
          data: finding.to_h
        )

        # If high/critical, also report as vuln
        if %w[critical high].include?(finding.severity)
          refs = finding.references.map do |ref|
            if ref.start_with?('CVE-')
              ref
            elsif ref.start_with?('http')
              "URL-#{ref}"
            else
              ref
            end
          end

          @framework.db.report_vuln(
            host: finding.host,
            port: finding.port,
            name: finding.title,
            info: finding.description,
            refs: refs
          )
        end
      rescue => e
        # Don't let DB errors stop the engine
        $stderr.puts("[!] DB storage error: #{e.message}")
      end
    end
  end
end
