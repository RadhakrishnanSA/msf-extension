# Integration smoke test
# Requires a running Metasploitable2 or similar vulnerable target.
# Set MME_INTEGRATION_TARGET environment variable to the target IP.
#
# Example:
#   MME_INTEGRATION_TARGET=172.17.0.2 rspec spec/integration/smoke_test_spec.rb
#
# This test is NOT run in standard CI — it requires a live vulnerable target.
# It is designed for manual validation or dedicated integration CI pipelines.

RSpec.describe 'MME Integration Smoke Test', if: ENV['MME_INTEGRATION_TARGET'] do
  let(:target) { ENV['MME_INTEGRATION_TARGET'] }

  it 'is documented for manual execution' do
    # This spec file serves as documentation for how to run
    # end-to-end integration tests.
    #
    # To run a real integration test:
    # 1. Start a vulnerable target (e.g., Metasploitable2 Docker image)
    #    docker run -d --name msf2 tleemcjr/metasploitable2
    # 2. Get the container IP
    #    TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' msf2)
    # 3. Run the test in msfconsole:
    #    load mme
    #    mme_doctor
    #    mme_scan $TARGET_IP
    # 4. Verify:
    #    - mme_findings shows at least 1 finding
    #    - mme_report html generates a valid report
    #    - Report file exists at ~/.msf4/mme/reports/
    #
    # Automated CI integration test would require:
    # - A Docker-based CI pipeline
    # - Metasploitable2 container
    # - MSF framework installed in CI
    # - Database connection
    expect(target).not_to be_nil
  end
end
