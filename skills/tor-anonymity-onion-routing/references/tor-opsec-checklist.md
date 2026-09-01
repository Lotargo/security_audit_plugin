# Tor OPSEC & Leak Prevention Checklist

1. **DNS Resolution**:
   - MUST resolve hostnames at the Tor exit node.
   - SOCKS5 protocol MUST specify `socks5h://` URI scheme.
   - `/etc/resolv.conf` in sandbox points exclusively to local dummy resolver or Tor DNS proxy (`127.0.0.1:5353`).

2. **WebRTC & Media Protocol**:
   - WebRTC MUST be disabled in headless Chromium (`--disable-webrtc`, `webrtc.iphandlingpolicy = disable_non_proxied_udp`).
   - STUN / TURN protocol requests MUST be blocked by nftables UDP egress rules.

3. **TLS & Fingerprinting**:
   - Never mix Tor anonymity with identifying cleartext HTTP headers (e.g. static cookies, client telemetry IDs).
   - Use JA3/JA4 TLS impersonation with matching Chrome browser headers.
