#!/bin/sh
set -e

echo "[*] Initializing Security Audit Docker Sandbox Environment..."

# Ensure unprivileged agent user exists in /etc/passwd and workspace is accessible
EXEC_UID="${AUDIT_EXEC_UID:-1001}"
EXEC_GID="${AUDIT_EXEC_GID:-1001}"
getent group "$EXEC_GID" >/dev/null 2>&1 || groupadd -g "$EXEC_GID" audit-agent 2>/dev/null || true
getent passwd "$EXEC_UID" >/dev/null 2>&1 || useradd -u "$EXEC_UID" -g "$EXEC_GID" -d /workspace -s /bin/bash audit-agent 2>/dev/null || true

# Ensure workspace and log directories exist
mkdir -p /workspace/logs /workspace/reports /workspace/plan /workspace/code
chown -R "$EXEC_UID:$EXEC_GID" /workspace
mkdir -p /etc/nftables

# Close all non-loopback egress before any network-capable helper starts. The daemon reapplies the
# same local policy on normal startup as defense in depth.
echo "[*] Applying bootstrap local egress isolation..."
/usr/local/bin/sandbox-daemon --bootstrap-local-egress

# Initialize Tor only after the bootstrap firewall is active. Tor can create external relay
# connections later only when an explicit tor-enabled scope installs the dedicated UID exception.
if command -v tor >/dev/null 2>&1; then
    echo "[*] Starting internal Tor daemon (localhost SOCKS5 9050 / cookie-auth ControlPort 9051)..."
    tor -f /etc/tor/torrc --quiet &
    TOR_PID=$!

    i=0
    while [ ! -s /var/lib/tor/control_auth_cookie ] && [ "$i" -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    if [ ! -s /var/lib/tor/control_auth_cookie ]; then
        echo "[!] Tor failed to initialize its control authentication cookie" >&2
        kill "$TOR_PID" 2>/dev/null || true
        exit 1
    fi
    echo "[+] Tor started with PID $TOR_PID"
fi

echo "[+] Launching Rust Sandbox Daemon on port ${PORT:-9999}..."
exec /usr/local/bin/sandbox-daemon
