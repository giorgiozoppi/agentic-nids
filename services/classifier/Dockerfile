FROM rust:1.81-bookworm AS builder

# protoc  — tonic-build needs it to compile the .proto file.
# libssl-dev — needed by openssl-sys when building with --features xgboost
#              (ort-sys pulls ureq → native-tls → openssl).
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY proto proto
COPY services/classifier services/classifier

WORKDIR /build/services/classifier

# Cache dep compilation before copying src (layer reused when only src changes).
RUN cargo fetch

# PROTO_DIR  — location of the shared .proto file (used by build.rs).
# BUILD_FEATURES — pass "--features xgboost" via docker build --build-arg to
#                  enable ONNX/OnnxRuntime inference.  Default: dummy only.
ENV PROTO_DIR=/build/proto
ARG BUILD_FEATURES=""

RUN if [ -n "${BUILD_FEATURES}" ]; then \
      cargo build --release --features "${BUILD_FEATURES}"; \
    else \
      cargo build --release; \
    fi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/services/classifier/target/release/classifier /classifier
ENTRYPOINT ["/classifier"]
