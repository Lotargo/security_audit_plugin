#!/bin/sh
set -e

echo "[*] Initializing Security Audit Docker Sandbox Environment..."

# Ensure workspace and log directories exist
mkdir -p /workspace/logs /workspace/reports /workspace/plan /workspace/code

# Initialize Tor daemon if available
if command -v tor >/dev/null 2>&1; then
    echo "[*] Starting internal Tor daemon (SOCKS5 9050 / ControlPort 9051)..."
    tor -f /etc/tor/torrc --quiet &
    TOR_PID=$!
    echo "[+] Tor started with PID $TOR_PID"
fi

# Ensure nftables rules directory exists
mkdir -p /etc/nftables

echo "[+] Launching Rust Sandbox Daemon on port ${PORT:-9999}..."
exec /usr/local/bin/sandbox-daemon
