//go:build linux

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/IceWhaleTech/CasaOS/pkg/publicfiles"
	"github.com/coreos/go-systemd/activation"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := execute(ctx, os.Args[1:], os.Stdout, productionDependencies()); err != nil {
		log.Printf("recasaos-public-files: %v", err)
		os.Exit(1)
	}
}

func productionDependencies() serveDependencies {
	return serveDependencies{
		validateRuntime: publicfiles.ValidateServiceRuntime,
		environ:         os.Environ,
		activationFiles: activation.Files,
		newPortal: func(config publicfiles.Config) (publicFilePortal, error) {
			return publicfiles.New(config)
		},
		newServer: func(handler http.Handler) publicFileHTTPServer {
			return publicfiles.NewHTTPServer(handler)
		},
		shutdownTimeout: gracefulShutdownLimit,
		connectionLimit: maxActiveConnections,
	}
}
