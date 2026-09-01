#!/bin/bash
set -euo pipefail

TOR_SOCKS="127.0.0.1:9050"
echo "[*] Checking Tor SOCKS5 connectivity..."

IP_INFO=$(curl -s --socks5-hostname "${TOR_SOCKS}" https://check.torproject.org/api/ip || echo "ERROR")

if [[ "${IP_INFO}" == *"IsTor\":true"* ]]; then
    echo "[+] SUCCESS: Traffic is properly routed through Tor network."
    echo "[+] Details: ${IP_INFO}"
else
    echo "[-] ALERT: Tor routing check failed or returned non-Tor address!"
    echo "[-] Response: ${IP_INFO}"
    exit 1
fi
