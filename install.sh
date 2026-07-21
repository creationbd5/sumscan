#!/bin/bash

# ===================================================================
# Project Name : SumScan - Automated Kali Linux Installer
# Author       : Sumon Mahmud
# GitHub       : https://github.com/creationbd5
# ===================================================================

echo "====================================================="
echo "   SUMSCAN - AUTOMATED INSTALLER FOR KALI LINUX     "
echo "====================================================="
echo ""

# Update System and Install Base Dependencies
echo "[+] Updating system packages and installing Python3 setup..."
sudo apt update -y
sudo apt install python3 python3-pip python3-tk git wget -y

# Install Python Libraries
echo "[+] Installing required Python libraries..."
pip3 install customtkinter pillow dnspython --break-system-packages

# Set Installation Directory
INSTALL_DIR="$HOME/SumScan"
APP_PATH="$INSTALL_DIR/sumscan.py"
ICON_PATH="$INSTALL_DIR/logo.png"

# Permissions
chmod +x "$APP_PATH"

# Create Desktop Entry Shortcut
echo "[+] Generating Application Menu and Desktop Shortcuts..."
DESKTOP_ENTRY="$HOME/.local/share/applications/sumscan.desktop"

cat <<EOF > "$DESKTOP_ENTRY"
[Desktop Entry]
Version=1.0
Type=Application
Name=SumScan
Comment=Web & Network Security Recon Suite
Exec=python3 $APP_PATH
Icon=$ICON_PATH
Terminal=false
Categories=01-info-gathering;03-webapp-analysis;Security;
Keywords=scanner;recon;security;penetration;
EOF

chmod +x "$DESKTOP_ENTRY"

# Copy shortcut to user's Desktop
if [ -d "$HOME/Desktop" ]; then
    cp "$DESKTOP_ENTRY" "$HOME/Desktop/"
    chmod +x "$HOME/Desktop/sumscan.desktop"
    gio set "$HOME/Desktop/sumscan.desktop" metadata::trusted true 2>/dev/null || true
fi

echo ""
echo "[✓] Installation Complete!"
echo "[+] SumScan desktop shortcut has been created."
echo "[+] Launching SumScan now..."
echo ""

# Launch Application
python3 "$APP_PATH" &
