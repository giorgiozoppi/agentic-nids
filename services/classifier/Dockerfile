FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=1 go build -o /classifier ./classifier/cmd

FROM debian:bookworm-slim
ARG ORT_VERSION=1.18.1
RUN apt-get update && apt-get install -y curl ca-certificates && \
    curl -fsSL \
      https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-${ORT_VERSION}.tgz \
      | tar -xz -C /usr/lib --strip-components=2 --wildcards "*/lib/*.so*" && \
    ldconfig && \
    apt-get remove -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /classifier /classifier
ENTRYPOINT ["/classifier"]
