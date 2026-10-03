# Rust-security pipeline target image: hyperium/h2 pinned at the pre-fix commit
# (v0.4.15), checked out for the agent to read, with a small tokio driver that
# plays attacker-controlled server frames to a default-config native h2 client.
# The oracle PoCs (targets/h2/poc/) are deliberately NOT copied into the image.
FROM rust:1-bookworm
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 xxd file gdb git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Same toolchain layer as the other rust targets (nightly + Miri + cargo-fuzz)
# so the run harness keeps its full detector ladder available.
RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src \
        --component llvm-tools-preview --component clippy \
    && rustup default nightly \
    && cargo install cargo-fuzz --locked

# The crate under audit, pinned at the vulnerable commit. History is stripped
# (`rm -rf .git`): the original harness ships tarballs/local copies precisely so
# the agent can't enumerate post-pin upstream fix commits (port-fidelity audit
# B1 — fix-guided "rediscovery" otherwise).
RUN git clone https://github.com/hyperium/h2 /work/h2 \
    && cd /work/h2 && git checkout -q 9416dc875da6d6b900eedc22636413c62dae912b \
    && rm -rf /work/h2/.git

COPY driver /work/driver
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh

ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1

# Build the driver against the pinned crate (path dep -> patch phase rebuilds
# pick up fixes to /work/h2). Also pre-warm the h2 test build for the patch
# grader's T2 tier.
RUN cd /work/driver && cargo build --bin riptarget \
    && cp target/debug/riptarget /work/riptarget
RUN cd /work/h2 && cargo test --lib --no-run

CMD ["/bin/bash"]
