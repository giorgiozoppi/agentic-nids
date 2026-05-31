.PHONY: proto build test build-test test-e2e docker-build docker-push clean help \
        build-agent build-classifier build-orchestrator build-search \
        test-agent test-classifier test-orchestrator test-search

REGISTRY   ?= ghcr.io
OWNER      ?= $(shell git config user.name | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
TAG        ?= $(shell git rev-parse --short HEAD)
PROTO_DIR  := proto

# ── proto codegen ──────────────────────────────────────────────────────────
proto:
	mkdir -p services/orchestrator/gen/classifierv1
	protoc \
	  --go_out=services/orchestrator/gen/classifierv1         \
	  --go_opt=paths=source_relative                          \
	  --go-grpc_out=services/orchestrator/gen/classifierv1    \
	  --go-grpc_opt=paths=source_relative                     \
	  --proto_path=$(PROTO_DIR)                               \
	  $(PROTO_DIR)/classifier.proto

# ── build ──────────────────────────────────────────────────────────────────
build-agent:
	cd services/agent && uv sync

build-classifier: proto
	cd services/classifier && PROTO_DIR=$(abspath $(PROTO_DIR)) cargo build --release

build-orchestrator: proto
	cd services/orchestrator && go build -o /tmp/nids-orchestrator ./cmd/...

build-search:
	cd services/search && cargo build --release

build: build-agent build-classifier build-orchestrator build-search

# ── run locally ────────────────────────────────────────────────────────────
# Start the gRPC classifier server in the foreground.
run-classifier: build-classifier
	./services/classifier/target/release/classifier --addr 0.0.0.0:50051

# Run one orchestrator batch against a local classifier and ClickHouse.
# Override variables as needed, e.g.:
#   make run-orchestrator CH_ADDR=localhost:9000 CLASSIFIER_ADDR=localhost:50051
CH_ADDR          ?= localhost:9000
CH_DB            ?= nids
CH_USER          ?= default
CH_PASSWORD      ?=
CLASSIFIER_ADDR  ?= localhost:50051
BATCH_SIZE       ?= 256
STATE_DIR        ?= /tmp/nids-state

run-orchestrator: build-orchestrator
	mkdir -p $(STATE_DIR)
	/tmp/nids-orchestrator \
	  -ch-addr=$(CH_ADDR) \
	  -ch-db=$(CH_DB) \
	  -ch-user=$(CH_USER) \
	  -ch-password=$(CH_PASSWORD) \
	  -classifier-addr=$(CLASSIFIER_ADDR) \
	  -batch-size=$(BATCH_SIZE) \
	  -state-dir=$(STATE_DIR)

# ── test ───────────────────────────────────────────────────────────────────
test-agent:
	cd services/agent && uv run pytest

test-classifier:
	cd services/classifier && PROTO_DIR=$(abspath $(PROTO_DIR)) cargo test

test-orchestrator: proto
	cd services/orchestrator && go test ./...

test-search:
	cd services/search && cargo test

# E2E test: starts the real classifier binary and exercises the gRPC path.
# Requires build-classifier to have been run first.
test-e2e: proto
	cd services/orchestrator && \
	  CLASSIFIER_BIN=$(abspath services/classifier/target/release/classifier) \
	  go test ./internal/grpcclient/... -tags e2e -v -run TestE2EClassifierComm -timeout 30s

test: test-agent test-classifier test-orchestrator test-search

# Build every service then run its full test suite — mirrors what CI does.
build-test: build test

# ── docker ─────────────────────────────────────────────────────────────────
docker-build:
	docker build -f services/agent/Dockerfile        -t $(REGISTRY)/$(OWNER)/nids-agent:$(TAG)        .
	docker build -f services/classifier/Dockerfile   -t $(REGISTRY)/$(OWNER)/nids-classifier:$(TAG)   .
	docker build -f services/orchestrator/Dockerfile -t $(REGISTRY)/$(OWNER)/nids-orchestrator:$(TAG) .
	docker build -f services/search/Dockerfile       -t $(REGISTRY)/$(OWNER)/nids-search:$(TAG)       .

docker-push: docker-build
	docker push $(REGISTRY)/$(OWNER)/nids-agent:$(TAG)
	docker push $(REGISTRY)/$(OWNER)/nids-classifier:$(TAG)
	docker push $(REGISTRY)/$(OWNER)/nids-orchestrator:$(TAG)
	docker push $(REGISTRY)/$(OWNER)/nids-search:$(TAG)

# ── infra ──────────────────────────────────────────────────────────────────
k8s-apply:
	kubectl apply -k infra/k8s/

k8s-diff:
	kubectl diff -k infra/k8s/

obs-install:
	helm repo add grafana https://grafana.github.io/helm-charts && helm repo update
	helm upgrade --install nids-observability infra/helm/observability \
	  --namespace observability --create-namespace --atomic --timeout 5m

obs-uninstall:
	helm uninstall nids-observability -n observability

# ── dev environment ────────────────────────────────────────────────────────
up:
	docker compose up -d

down:
	docker compose down

# ── clean ──────────────────────────────────────────────────────────────────
clean:
	rm -rf services/orchestrator/gen/
	cd services/classifier && cargo clean
	cd services/search && cargo clean

help:
	@grep -E '^[a-zA-Z_-]+:' $(MAKEFILE_LIST) | grep -v '^\.' | \
	  awk -F: '{printf "  %-26s\n", $$1}'
