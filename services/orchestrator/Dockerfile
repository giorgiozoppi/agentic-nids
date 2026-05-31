FROM golang:1.22-bookworm AS builder

# protoc + Go plugins for proto generation inside Docker
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/* \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.4.0

WORKDIR /build
COPY proto proto
COPY services/orchestrator services/orchestrator

WORKDIR /build/services/orchestrator

RUN mkdir -p gen/classifierv1 \
    && protoc \
         --go_out=gen/classifierv1         --go_opt=paths=source_relative \
         --go-grpc_out=gen/classifierv1    --go-grpc_opt=paths=source_relative \
         --proto_path=/build/proto \
         /build/proto/classifier.proto

RUN go mod download && go build -o /orchestrator ./cmd

FROM gcr.io/distroless/base-debian12
COPY --from=builder /orchestrator /orchestrator
ENTRYPOINT ["/orchestrator"]
