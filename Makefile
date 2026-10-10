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
