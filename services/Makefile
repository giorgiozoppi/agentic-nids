.PHONY: proto build-classifier build-orchestrator build all clean

# Generate gRPC/protobuf code
proto:
	protoc \
	  --go_out=gen --go_opt=paths=source_relative \
	  --go-grpc_out=gen --go-grpc_opt=paths=source_relative \
	  --proto_path=proto \
	  proto/classifier.proto

# Build classifier binary (CGO required for microsoft/onnxruntime-go)
build-classifier:
	CGO_ENABLED=1 go build -o bin/classifier ./classifier/cmd

# Build orchestrator binary
build-orchestrator:
	go build -o bin/orchestrator ./orchestrator/cmd

build: build-classifier build-orchestrator

all: proto build

clean:
	rm -rf bin/ gen/classifierv1/

# Docker image targets
docker-classifier:
	docker build -f classifier/Dockerfile -t nids/classifier:latest .

docker-orchestrator:
	docker build -f orchestrator/Dockerfile -t nids/orchestrator:latest .
