#!/bin/bash
# MME Installation Script

MSF_DIR="$HOME/.msf4"
MME_DIR="$MSF_DIR/mme"
PLUGIN_FILE="$MSF_DIR/plugins/mme.rb"

# Handle uninstallation
if [ "$1" == "--uninstall" ]; then
    echo "[*] Uninstalling MME..."
    rm -rf "$MME_DIR"
    rm -f "$PLUGIN_FILE"
    echo "[+] Uninstalled."
    exit 0
fi

echo "[*] Installing Metasploit Methodology Engine (MME)..."

# Check prerequisites
if ! command -v msfconsole &> /dev/null; then
    echo "[-] Metasploit Framework could not be found. Please install it first."
    exit 1
fi

# Create directories
mkdir -p "$MME_DIR"
mkdir -p "$MSF_DIR/plugins"

# Copy files
echo "[*] Copying files to $MME_DIR..."
cp -r lib playbooks templates "$MME_DIR/"
cp mme.rb "$PLUGIN_FILE"

# Set permissions
chmod -R 755 "$MME_DIR"

echo "[+] Installation complete!"
echo "[*] To start using MME, launch msfconsole and type: load mme"
