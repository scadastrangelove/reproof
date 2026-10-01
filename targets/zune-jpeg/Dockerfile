FROM rust:1-bookworm
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends python3 file gdb \
    && rm -rf /var/lib/apt/lists/*
COPY crate /work/crate
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh
ENV RUST_BACKTRACE=1
# Detection build: overflow-checks + debug-assertions ON. P0.1 requires re-testing
# any arithmetic-overflow crash under the SHIPPING build before grading it real.
RUN cd /work/crate && RUSTFLAGS="-C overflow-checks=on -C debug-assertions=on" \
        cargo build --release --bin riptarget \
    && cp target/release/riptarget /work/riptarget
CMD ["/bin/bash"]
