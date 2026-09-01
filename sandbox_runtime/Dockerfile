# ==============================================================================
# Stage 1: Rust Builder
# ==============================================================================
FROM rust:1.98-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace sources
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# Build release binaries with the same Rust line used by CI.
RUN cargo build --locked --release --bin sandbox-daemon

# ==============================================================================
# Stage 2: Minimal & Hardened Kali Security Runtime
# ==============================================================================
FROM kalilinux/kali-rolling

LABEL maintainer="Lotargo & Antigravity"
LABEL description="Hardened Docker Sandbox with Rust Kernel, Node.js Stealth Browser, Tor & Security Tools"

ENV DEBIAN_FRONTEND=noninteractive
ENV PORT=9999
ENV CHROMIUM_PATH=/usr/bin/chromium
ENV NODE_PATH=/opt/stealth/node_modules

# Keep the explicit package list limited to top-level capabilities. Chromium's required
# rendering/audio libraries are installed by apt as dependencies, avoiding brittle distro-
# specific package names (for example Debian/Kali t64 transitions).
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    tor \
    nftables \
    conntrack \
    tmux \
    curl \
    wget \
    ca-certificates \
    git \
    jq \
    procps \
    nodejs \
    npm \
    chromium \
    chromium-driver \
    nmap \
    subfinder \
    sqlmap \
    nikto \
    yara \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 2. Setup Tor configuration
COPY tor/torrc /etc/tor/torrc
RUN mkdir -p /var/lib/tor && chown -R root:root /var/lib/tor

# 3. Setup Node.js Stealth Browser Tier
WORKDIR /opt/stealth
COPY stealth/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY stealth/*.js stealth/waf_profiles.json ./

# 4. Copy compiled Rust daemon binary from builder
COPY --from=builder /usr/src/app/target/release/sandbox-daemon /usr/local/bin/sandbox-daemon
RUN chmod +x /usr/local/bin/sandbox-daemon

# 5. Copy and configure entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 6. Setup workspace directory for mounted volumes & logs
WORKDIR /workspace
RUN mkdir -p /workspace/logs /workspace/reports /workspace/plan /workspace/code

EXPOSE 9999
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
