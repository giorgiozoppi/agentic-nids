.PHONY: build test docker run

REGISTRY ?= ghcr.io
OWNER    ?= $(shell git -C ../.. config user.name | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
TAG      ?= latest
IMAGE    := nids-collector:$(TAG)

# Install / sync Python dependencies
build:
	uv sync

# Run the unit-test suite
test:
	uv run pytest

# Run the collector in the foreground (root required for live capture)
# Override the interface: make run INTERFACE=eth0
INTERFACE ?= $(CAPTURE_INTERFACE)
run: build
	sudo -E uv run nids-collector --interface $(INTERFACE)

# Build the collector Docker image (context must be the repo root)
docker:
	docker build \
	  -f Dockerfile \
	  -t $(IMAGE) \
	  ../..
