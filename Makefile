BINARY  := omenhound
PKG     := github.com/krazybeastx1/omenhound
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION)

# Where the NetExec module is installed. nxc loads user modules from
# ~/.nxc/modules/ (filename must equal the module name).
NXC_MODULES ?= $(HOME)/.nxc/modules

.PHONY: all build install install-nxc uninstall-nxc test vet lint fmt clean run-sample test-ui test-nxc

all: vet test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/omenhound

install: install-nxc
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/omenhound

# Copy contrib/nxc/omenhound.py into the user's nxc modules dir. The loader
# requires the filename to equal the module name, so it must stay omenhound.py.
install-nxc:
	install -d "$(NXC_MODULES)"
	install -m 0644 contrib/nxc/omenhound.py "$(NXC_MODULES)/omenhound.py"
	@echo "installed $(NXC_MODULES)/omenhound.py — verify: nxc smb -M omenhound --list-modules"

uninstall-nxc:
	rm -f "$(NXC_MODULES)/omenhound.py"

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

# Graph Explorer UX tests. Needs Selenium + system Chromium. Runs the read-only
# checks against a scratch server and ingests a self-contained fixture into it
# (so it never touches a real dataset). Point BASE at an existing server to test
# its dataset read-only instead.
BASE     ?= http://127.0.0.1:18192
UI_TOKEN ?= operator-secret
test-ui: build
	./bin/$(BINARY) serve --collector none --addr 127.0.0.1:18192 --api-token "$(UI_TOKEN)" & \
	srv=$$!; sleep 2; \
	python3 scripts/graph_ux_test.py --base http://127.0.0.1:18192 --token "$(UI_TOKEN)" --ingest; \
	rc=$$?; kill $$srv 2>/dev/null; exit $$rc

# Publish wiki/*.md to the project GitHub wiki (see wiki/README.md).
wiki:
	scripts/publish-wiki.sh

# Offline tests for the NetExec module in contrib/nxc (python3 only; no AD, nxc or
# live server required — the script stubs the OmenHound API contract).
test-nxc:
	python3 scripts/nxc_omenhound_test.py
