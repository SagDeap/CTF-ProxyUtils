BINARY  := ctf-proxyutils
PKG     := ./cmd/ctf-proxyutils
VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Цели сборки. macOS и Windows тут не ради vulnbox, а на случай, когда
# пробросить порт нужно с чьего-то ноутбука.
PLATFORMS := linux/amd64 linux/arm64 linux/386 linux/arm \
             darwin/amd64 darwin/arm64 windows/amd64

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

## dist — статические бинарники под все платформы плюс контрольные суммы.
## Нужен официальный toolchain с go.dev: gccgo кросс-компиляцию не умеет.
## Версия переопределяется извне: make dist VERSION=v0.1.0
dist:
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out="dist/$(BINARY)-$$os-$$arch"; \
		if [ "$$os" = "windows" ]; then out="$$out.exe"; fi; \
		echo "  сборка $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -ldflags "$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
	@cd dist && sha256sum * > checksums.txt
	@echo "готово:" && ls -lh dist/
