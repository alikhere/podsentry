BINARY   := podsentry
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  := -ldflags "-X github.com/alikhere/podsentry/pkg/version.Version=$(VERSION) \
                      -X github.com/alikhere/podsentry/pkg/version.GitCommit=$(COMMIT) \
                      -X github.com/alikhere/podsentry/pkg/version.BuildDate=$(DATE)"

.PHONY: build test lint clean install tidy

build:
	go build $(LDFLAGS) -o $(BINARY) ./main.go

test:
	go test ./... -v -cover

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)

install:
	go install $(LDFLAGS) ./...

tidy:
	go mod tidy
