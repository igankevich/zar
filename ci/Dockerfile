FROM rust:1.80.1

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get -qq update \
    && apt-get -qq install --no-install-recommends \
    pre-commit \
    python3-pip \
    libclang-dev \
    shellcheck \
    clang \
    curl \
    lcov \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    RUST_VERSION=1.80.1 \
    PATH=/usr/local/cargo/bin:$PATH

RUN rustup toolchain add nightly \
    --target x86_64-unknown-linux-gnu \
    --component rustfmt miri llvm-tools-preview
RUN rustup toolchain add 1.80.1 \
    --target x86_64-unknown-linux-gnu \
    --component clippy rustfmt llvm-tools-preview
RUN rustup target add --toolchain 1.80.1 \
    x86_64-unknown-linux-musl
RUN rustup default 1.80.1-x86_64-unknown-linux-gnu
RUN cargo install --quiet --no-default-features --features native-certs cargo-deny

RUN curl --location --silent --fail --output /usr/local/bin/shfmt https://github.com/mvdan/sh/releases/download/v3.8.0/shfmt_v3.8.0_linux_amd64 && \
    chmod +x /usr/local/bin/shfmt

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get -qq update \
    && apt-get -qq install --no-install-recommends \
    liblzma-dev \
    libbz2-dev \
    jq \
    musl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/mackyle/xar /tmp/xar \
    && cd /tmp/xar/xar \
    && sed -i -e 's/OpenSSL_add_all_ciphers/CRYPTO_free/g' configure.ac \
    && autoconf \
    && ./configure --prefix=/usr \
    && make \
    && make install \
    && cd /tmp \
    && rm -rf /tmp/xar

LABEL org.opencontainers.image.source=https://github.com/igankevich/zar
LABEL org.opencontainers.image.description="CI image"

CMD ["/bin/bash"]
