# ==============================================================================
# Stage 1: Rust Builder
# ==============================================================================
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace sources
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# Build release binaries
RUN cargo build --release --bin sandbox-daemon

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

# 1. Update and install base runtime, system tools, Tor & networking
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
    # Headless Chromium & rendering dependencies
    chromium \
    chromium-driver \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libxkbcommon0 \
    libpango-1.0-0 \
    libasound2 \
    # Pre-installed DAST/SAST Arsenal
    nmap \
    subfinder \
    sqlmap \
    nikto \
    yara \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 2. Setup Tor configuration
COPY tor/torrc /etc/tor/torrc
RUN mkdir -p /var/lib/tor && chown -R root:root /var/lib/tor

# 3. Setup Node.js Stealth Browser Tier
WORKDIR /opt/stealth
COPY stealth/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY stealth/*.js ./

# 4. Copy compiled Rust daemon binary from builder
COPY --from=builder /usr/src/app/target/release/sandbox-daemon /usr/local/bin/sandbox-daemon
RUN chmod +x /usr/local/bin/sandbox-daemon

# 5. Copy and configure entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 6. Setup workspace directory for mounted volumes & logs
WORKDIR /workspace
RUN mkdir -p /workspace/logs /workspace/reports /workspace/plan /workspace/code

# Expose internal management port
EXPOSE 9999

# Run under tini init process
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
