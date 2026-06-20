# Installation Guide

## Prerequisites
* Metasploit Framework (installed and configured)
* PostgreSQL Database (running and connected via `db_connect` in MSF)
* Nmap (required for `mme_scan`)
* Ruby

## Method 1: Automated Installation (Linux/macOS)
1. Clone the repository:
   ```bash
   git clone https://github.com/RadhakrishnanSA/msf-extension.git
   cd msf-extension
   ```
2. Make the script executable and run it:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```
3. Load the plugin in msfconsole:
   ```bash
   msfconsole
   msf6 > load mme
   ```

## Method 2: Manual Installation
1. Create the MME directory in your local MSF folder:
   ```bash
   mkdir -p ~/.msf4/mme
   ```
2. Copy the directories:
   ```bash
   cp -r lib playbooks templates ~/.msf4/mme/
   ```
3. Copy the plugin file:
   ```bash
   cp mme.rb ~/.msf4/plugins/
   ```
4. Load the plugin in msfconsole:
   ```bash
   msfconsole
   msf6 > load mme
   ```

## Uninstallation
Run `./install.sh --uninstall` or manually remove `~/.msf4/plugins/mme.rb` and the `~/.msf4/mme/` directory.
