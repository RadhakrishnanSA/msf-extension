require 'erb'
require 'json'
require 'fileutils'
require 'time'

module Mme
  class ReportGenerator
    include ERB::Util

    def initialize(template_dir)
      @template_dir = template_dir
    end

    def generate_html(findings, evidence, metadata)
      template_path = File.join(@template_dir, 'report.html.erb')

      unless File.exist?(template_path)
        # Use inline template if file not found
        template_content = default_html_template
      else
        template_content = File.read(template_path)
      end

      # Sort findings by severity
      sorted_findings = findings.sort_by { |f| Finding::SEVERITIES.index(f.severity.to_s.downcase) || 99 }

      # Group by host
      findings_by_host = sorted_findings.group_by(&:host)

      # Severity summary
      severity_summary = Hash.new(0)
      sorted_findings.each { |f| severity_summary[f.severity] += 1 }

      # Render template
      erb = ERB.new(template_content, trim_mode: '-')
      html = erb.result(binding)

      output_path = report_output_path('html')
      File.write(output_path, html)
      output_path
    end

    def generate_markdown(findings, evidence, metadata)
      template_path = File.join(@template_dir, 'report.md.erb')
      
      unless File.exist?(template_path)
        log_error("Markdown template not found at #{template_path}")
        return nil
      end
      
      template_content = File.read(template_path)

      # Sort findings by severity
      sorted_findings = findings.sort_by { |f| Finding::SEVERITIES.index(f.severity.to_s.downcase) || 99 }

      # Group by host
      findings_by_host = sorted_findings.group_by(&:host)

      # Severity summary
      severity_summary = Hash.new(0)
      sorted_findings.each { |f| severity_summary[f.severity] += 1 }

      # Render template
      erb = ERB.new(template_content, trim_mode: '-')
      markdown = erb.result(binding)

      # Save report
      output_path = report_output_path('md')
      File.write(output_path, markdown)
      output_path
    end

    def generate_json(findings, evidence, metadata)
      report = {
        metadata: {
          tool: metadata[:tool_name] || 'Metasploit Methodology Engine',
          version: metadata[:tool_version] || Mme::VERSION,
          generated_at: Time.now.iso8601,
          target: metadata[:target],
          start_time: metadata[:start_time]&.iso8601,
          end_time: metadata[:end_time]&.iso8601,
          duration_seconds: metadata[:duration]
        },
        summary: {
          hosts_scanned: metadata[:hosts_scanned] || 0,
          services_found: metadata[:services_found] || 0,
          findings_total: findings.size,
          evidence_total: evidence.size,
          by_severity: findings.group_by(&:severity).transform_values(&:count)
        },
        findings: findings.map(&:to_h),
        evidence: evidence.map { |e|
          {
            id: e.id, host: e.host, port: e.port, service: e.service,
            module_path: e.module_path, type: e.evidence_type,
            content: e.content, timestamp: e.timestamp&.to_s
          }
        }
      }

      output_path = report_output_path('json')
      File.write(output_path, JSON.pretty_generate(report))
      output_path
    end

    def generate_pdf(findings, evidence, metadata)
      raise NotImplementedError, 'PDF generation will be available in a future version'
    end

    private

    def report_output_path(extension)
      dir = File.join(Dir.home, '.msf4', 'mme', 'reports')
      FileUtils.mkdir_p(dir)
      timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
      File.join(dir, "mme_report_#{timestamp}.#{extension}")
    end

    # Fallback HTML template if the ERB file is not found
    def default_html_template
      # (This is a simplified fallback; the full template is in templates/report.html.erb)
      <<~'HTML'
      <!DOCTYPE html>
      <html><head><title>MME Report</title>
      <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; } h2 { color: #0f3460; background: #16213e; padding: 10px; border-radius: 4px; color: #eee; }
        .finding { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #e94560; }
        .critical { border-left-color: #ff0000; } .high { border-left-color: #ff4444; }
        .medium { border-left-color: #ffaa00; } .low { border-left-color: #00aaff; }
        .info { border-left-color: #888; }
        .badge { padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
        .badge-critical { background: #ff0000; } .badge-high { background: #ff4444; }
        .badge-medium { background: #ffaa00; color: #333; } .badge-low { background: #00aaff; }
        .badge-informational { background: #888; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; }
        pre { background: #0d1117; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card .number { font-size: 32px; font-weight: bold; color: #e94560; }
        .summary-card .label { font-size: 14px; color: #aaa; margin-top: 5px; }
      </style></head><body>
      <h1>🔍 Metasploit Methodology Engine — Report</h1>
      <p>Generated: <%= Time.now %></p>
      <p>Target: <%= h(metadata[:target]) %></p>

      <h2>Executive Summary</h2>
      <div class="summary-grid">
        <div class="summary-card"><div class="number"><%= sorted_findings.size %></div><div class="label">Total Findings</div></div>
        <% Finding::SEVERITIES.each do |sev| %>
          <div class="summary-card"><div class="number"><%= severity_summary[sev] || 0 %></div><div class="label"><%= sev.capitalize %></div></div>
        <% end %>
      </div>

      <h2>Findings by Host</h2>
      <% if findings_by_host.empty? %>
        <p>No findings discovered.</p>
      <% else %>
      <% findings_by_host.each do |host, host_findings| %>
        <h3>Host: <%= h(host) %></h3>
        <% host_findings.each do |f| %>
          <div class="finding <%= h(f.severity) %>">
            <span class="badge badge-<%= h(f.severity) %>"><%= h(f.severity.upcase) %></span>
            <strong><%= h(f.title) %></strong>
            <p><%= h(f.description) %></p>
            <table>
              <tr><th>Service</th><td><%= h(f.service) %> (Port <%= f.port %>)</td></tr>
              <tr><th>Module</th><td><%= h(f.module_path) %></td></tr>
              <tr><th>Impact</th><td><%= h(f.impact) %></td></tr>
              <tr><th>Remediation</th><td><%= h(f.remediation) %></td></tr>
              <tr><th>Status</th><td><%= h(f.status) %></td></tr>
            </table>
            <% if f.evidence.is_a?(Array) && f.evidence.any? %>
              <h4>Evidence</h4>
              <% f.evidence.each do |ev| %>
                <pre><%= h(ev.to_s) %></pre>
              <% end %>
            <% end %>
          </div>
        <% end %>
      <% end %>
      <% end %>

      <hr>
      <p><em>Generated by MME v<%= Mme::VERSION %> | Duration: <%= metadata[:duration] %>s</em></p>
      </body></html>
      HTML
    end
  end
end
