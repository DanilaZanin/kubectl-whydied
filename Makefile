# kubectl-whydied developer entry points.
BIN        := bin/kubectl-whydied
PKG        := github.com/DanilaZanin/kubectl-whydied
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS    := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GOTESTFLAGS ?=

# Node images used by the e2e matrix. Override NODE_IMAGE to test another one.
NODE_IMAGE ?= kindest/node:v1.37.0
E2E_TIMEOUT ?= 60m

.PHONY: krew-manifest build vet lint test e2e e2e-all snapshot fmt tidy clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/kubectl-whydied

vet:
	go vet ./...
	go vet -tags e2e ./test/...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w cmd internal test

tidy:
	go mod tidy

test:
	go test $(GOTESTFLAGS) ./...

# Real e2e on a kind cluster. Needs docker, kind and kubectl on PATH.
# WD_E2E_SCENARIOS is a regexp that selects scenarios, for example 'oom|exit1'.
e2e:
	WD_E2E_NODE_IMAGE=$(NODE_IMAGE) go test -tags e2e -count=1 -timeout $(E2E_TIMEOUT) -v ./test/e2e/...

e2e-all:
	$(MAKE) e2e NODE_IMAGE=kindest/node:v1.31.12
	$(MAKE) e2e NODE_IMAGE=kindest/node:v1.37.0

snapshot:
	goreleaser release --snapshot --clean --skip=publish

clean:
	rm -rf bin dist

# Fill plugins/whydied.yaml from dist/checksums.txt (after make snapshot or a release build).
krew-manifest:
	scripts/krew-manifest.sh $(VERSION) dist/checksums.txt
