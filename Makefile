.PHONY: all build test lint vet tidy server client probe docker run-server run-client clean

GO ?= go
BIN := bin
LDFLAGS := -s -w

all: build

build: server client probe

server:
	$(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $(BIN)/pmt-server ./cmd/server

client:
	$(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $(BIN)/pmt-client ./cmd/client

probe:
	$(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $(BIN)/pmt-probe ./cmd/probe

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

docker:
	docker build -f deploy/Dockerfile -t pmt-server:dev .

run-server:
	PMT_AUTH_KEY=$${PMT_AUTH_KEY:-localdevkey-must-be-16-bytes-or-more} \
	  $(BIN)/pmt-server

run-client:
	$(BIN)/pmt-client --config examples/client-config.json

clean:
	rm -rf $(BIN)
