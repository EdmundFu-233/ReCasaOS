.PHONY: build build-ui build-backend help

build: build-backend


build-ui:
	@echo "UI build disabled: pin a reviewed UI gitlink in RECASAOS_COMPONENTS.md first"
	@exit 1

build-backend:
	export CGO_ENABLED=1;export CGO_LDFLAGS=-static;go build -o ./casa main.go;upx --lzma --best casa

help:
	@echo "build: build the ReCasaOS root backend"
	@echo "build-ui: disabled until the UI component is pinned"
