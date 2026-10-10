BINARY  := omenhound
PKG     := github.com/krazybeastx1/omenhound
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION)

.PHONY: all build install test vet lint fmt clean run-sample

all: vet test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/omenhound

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/omenhound

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin dist coverage.txt

# Demo: collect the bundled sample graph, serve the API/UI, and open http://127.0.0.1:8080
run-sample: build
	./bin/$(BINARY) serve --collector sample --addr 127.0.0.1:8080

.PHONY: shots wiki

# Capture the wiki screenshots (Selenium + system Chromium).
shots: build
	./bin/$(BINARY) serve --collector sample --addr 127.0.0.1:18091 --api-token operator-secret & \
	srv=$$!; sleep 2; \
	python3 scripts/shots.py http://127.0.0.1:18091 wiki/img; \
	rc=$$?; kill $$srv 2>/dev/null; exit $$rc

# Publish wiki/*.md to the project GitHub wiki (see wiki/README.md).
wiki:
	scripts/publish-wiki.sh
