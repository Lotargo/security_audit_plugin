# ==============================================================================
# Stage 1: Rust Builder
# ==============================================================================
FROM rust:1.98-slim-bookworm AS builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
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
# specific package names during rolling transitions. util-linux provides setpriv for
# unprivileged tmux pane shells.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    tor \
    nftables \
    conntrack \
    tmux \
    util-linux \
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

# Fixed, non-root identities for privileged managed network clients. These UIDs are reserved by
# sandbox-kernel and must never overlap the host-compatible AUDIT_EXEC_UID used by agent shells.
RUN groupadd --gid 65531 audit-tor \
    && useradd --uid 65531 --gid 65531 --no-create-home --home-dir /var/lib/tor --shell /usr/sbin/nologin audit-tor \
    && groupadd --gid 65532 audit-browser \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /tmp --shell /usr/sbin/nologin audit-browser

COPY tor/torrc /etc/tor/torrc
RUN mkdir -p /var/lib/tor \
    && chown -R audit-tor:audit-tor /var/lib/tor \
    && chmod 0700 /var/lib/tor

WORKDIR /opt/stealth
COPY stealth/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY stealth/*.js stealth/waf_profiles.json ./

COPY --from=builder /usr/src/app/target/release/sandbox-daemon /usr/local/bin/sandbox-daemon
RUN chmod +x /usr/local/bin/sandbox-daemon

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /workspace
RUN mkdir -p /workspace/logs /workspace/reports /workspace/plan /workspace/code

EXPOSE 9999
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
