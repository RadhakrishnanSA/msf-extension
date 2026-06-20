# Metasploit Methodology Engine (MME)
# A Metasploit Framework plugin that automates penetration testing methodologies
#
# Author: RadhakrishnanSA
# Version: 1.0.0
# License: MIT

# Determine the MME library path
mme_base = File.join(Dir.home, '.msf4', 'mme')
$LOAD_PATH.unshift(mme_base) unless $LOAD_PATH.include?(mme_base)

# Also try loading from the current extension path for dev mode
ext_base = File.expand_path('.', __dir__)
$LOAD_PATH.unshift(ext_base) unless $LOAD_PATH.include?(ext_base)

# Load MME components
require 'lib/mme/version'
require 'lib/mme/finding'
require 'lib/mme/output_capture'
require 'lib/mme/service_queue'
require 'lib/mme/playbook'
require 'lib/mme/module_runner'
require 'lib/mme/evidence_collector'
require 'lib/mme/playbook_engine'
require 'lib/mme/scanner'
require 'lib/mme/report_generator'
require 'lib/mme/engine'
require 'lib/mme/console_dispatcher'

module Msf
  class Plugin::Mme < Msf::Plugin

    def initialize(framework, opts)
      super
      add_console_dispatcher(::Mme::ConsoleDispatcher)
      print_status(::Mme::BANNER)
      print_status('Type "mme_help" for usage information.')
      print_good('MME plugin loaded successfully.')
    end

    def cleanup
      remove_console_dispatcher('MME')
      print_status('MME plugin unloaded.')
    end

    def name
      'mme'
    end

    def desc
      'Metasploit Methodology Engine - Automated penetration testing methodology plugin'
    end
  end
end
