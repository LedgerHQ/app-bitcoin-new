# An image derived from ledgerhq/speculos but also containing the bitcoin-core binaries
# compiled from the master branch

# ==========================================
# STAGE 1: Builder
# ==========================================
FROM ghcr.io/ledgerhq/speculos:latest AS builder

# 1. Combine apt commands, prevent interactive prompts, and skip recommended bloatware.
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config ccache git curl bsdmainutils \
    libboost-dev libboost-filesystem-dev libboost-system-dev libboost-test-dev \
    libevent-dev libminiupnpc-dev libnatpmp-dev libqt5gui5 libqt5core5a \
    libqt5dbus5 libsqlite3-dev libtool libzmq3-dev python3 qttools5-dev \
    qttools5-dev-tools qtwayland5 systemtap-sdt-dev && \
    rm -rf /var/lib/apt/lists/*

# 2. Clone and compile. Use -j to build using all available CPU cores!
RUN git clone --depth=1 https://github.com/bitcoin/bitcoin.git /bitcoin && \
    cd /bitcoin && \
    cmake -B build -DENABLE_IPC=OFF && \
    cmake --build build -j"$(nproc)" && \
    cmake --install build

# ==========================================
# STAGE 2: Runtime
# ==========================================
FROM ghcr.io/ledgerhq/speculos:latest

# Copy the compiled binaries from Stage 1
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# 3. Clean up the runtime dependencies.
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl git libminiupnpc-dev libnatpmp-dev libevent-dev libzmq3-dev && \
    rm -rf /var/lib/apt/lists/*

# Add bitcoin binaries to path
ENV PATH="/usr/local/bin/:${PATH}"
