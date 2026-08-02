BINARY  := ctf-proxyutils
PKG     := ./cmd/ctf-proxyutils
VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build run test vet clean dist

all: build

## build — собрать бинарник под текущую систему
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## run — собрать и запустить
run: build
	./$(BINARY)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BINARY) dist

## dist — кросс-компиляция под всё, на чём может оказаться виртуалка.
## Нужен официальный toolchain с go.dev: gccgo кросс-собирать не умеет.
dist:
	mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64   $(PKG)
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64   $(PKG)
	GOOS=linux  GOARCH=386   CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-386     $(PKG)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64  $(PKG)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64  $(PKG)
	@echo "готово:" && ls -lh dist/
