# Rust-security pipeline target image: rustls pinned at the pre-fix commit
# (0.24.0-dev.1), checked out for the agent to read, with a driver that feeds
# attacker handshake bytes to a QUIC server built on a mixed-compatibility
# CryptoProvider. The oracle PoCs (targets/rustls/poc/) are NOT in the image.
FROM rust:1-bookworm
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 xxd file gdb git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src \
        --component llvm-tools-preview --component clippy \
    && rustup default nightly \
    && cargo install cargo-fuzz --locked

# The crate under audit, pinned at the vulnerable commit.
RUN git clone https://github.com/rustls/rustls /work/rustls \
    && cd /work/rustls && git checkout -q bd9f7f59aa79

COPY driver /work/driver
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh

ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1

# Build the driver against the pinned workspace (path deps -> patch-phase
# rebuilds pick up fixes to /work/rustls). Pre-warm the rustls lib test build
# for the patch grader's T2 tier.
RUN cd /work/driver && cargo build --bin riptarget \
    && cp target/debug/riptarget /work/riptarget
RUN cd /work/rustls/rustls && cargo test --lib --no-run

CMD ["/bin/bash"]
