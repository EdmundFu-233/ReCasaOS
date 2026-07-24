.PHONY: build build-ui build-backend build-public-files help

PUBLIC_FILES_BINARY := build/sysroot/usr/lib/recasaos-public-files/rootfs/usr/bin/recasaos-public-files

build: build-backend


build-ui:
	@echo "UI build disabled: pin a reviewed UI gitlink in RECASAOS_COMPONENTS.md first"
	@exit 1

build-backend:
	export CGO_ENABLED=1;export CGO_LDFLAGS=-static;go build -o ./casa main.go;upx --lzma --best casa

build-public-files:
	mkdir -p $(dir $(PUBLIC_FILES_BINARY))
	CGO_ENABLED=0 GOOS=linux go build -trimpath -tags "netgo osusergo" -o $(PUBLIC_FILES_BINARY) ./cmd/recasaos-public-files

help:
	@echo "build: build the ReCasaOS root backend"
	@echo "build-public-files: build the static public-file service"
	@echo "build-ui: disabled until the UI component is pinned"
