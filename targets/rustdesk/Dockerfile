# Rust-security pipeline target image: rustdesk/hbb_common pinned at the
# pre-fix commit. Two stages:
#   gen    — builds the challenge with the REAL production encryption path
#            (hbb_common::tcp::Encrypt); the shared key and peer-B plaintext
#            exist only in this stage's process memory and never reach the
#            final image.
#   final  — the crate under audit at /work/hbb_common + the challenge JSON
#            (public material + sha256 of the answer only) + the driver.
FROM rust:1-bookworm AS gen
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates pkg-config libsodium-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/rustdesk/hbb_common /work/hbb_common \
    && cd /work/hbb_common && git checkout -q 69cea8da
COPY gen /gen
RUN cd /gen && cargo run --release -q > /challenge.json

FROM rust:1-bookworm
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 xxd file gdb git ca-certificates pkg-config libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

# Same toolchain layer as the other rust targets (nightly + Miri + cargo-fuzz).
RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src \
        --component llvm-tools-preview --component clippy \
    && rustup default nightly \
    && cargo install cargo-fuzz --locked

# The crate under audit, pinned at the vulnerable commit (agent reads it here).
RUN git clone https://github.com/rustdesk/hbb_common /work/hbb_common \
    && cd /work/hbb_common && git checkout -q 69cea8da

COPY --from=gen /challenge.json /work/challenge.json
COPY driver /work/driver
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh

ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1

RUN cd /work/driver && cargo build --release --bin riptarget \
    && cp target/release/riptarget /work/riptarget

CMD ["/bin/bash"]
