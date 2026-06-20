require 'rspec'
require_relative '../lib/mme/finding'
require_relative '../lib/mme/evidence_collector'
require_relative '../lib/mme/playbook'

RSpec.describe Mme::Finding do
  it 'assigns a default id' do
    finding = Mme::Finding.new
    expect(finding.id).not_to be_nil
  end

  it 'sorts by severity correctly' do
    f1 = Mme::Finding.new(severity: 'low')
    f2 = Mme::Finding.new(severity: 'critical')
    f3 = Mme::Finding.new(severity: 'high')

    sorted = [f1, f2, f3].sort
    expect(sorted.map(&:severity)).to eq(%w[critical high low])
  end
end

RSpec.describe Mme::Playbook do
  it 'matches service aliases correctly' do
    pb = Mme::Playbook.new(service: 'http')
    expect(pb.matches_service?('http')).to be true
    expect(pb.matches_service?('www')).to be true
    expect(pb.matches_service?('ftp')).to be false
  end
end
