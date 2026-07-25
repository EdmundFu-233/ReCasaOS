//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/IceWhaleTech/CasaOS/pkg/publicfiles"
	"github.com/coreos/go-systemd/activation"
	"github.com/coreos/go-systemd/daemon"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == publicfiles.InternalStorageWorkerArgument {
		if err := publicfiles.RunInternalStorageWorker(os.Args[2]); err != nil {
			os.Exit(125)
		}
		return
	}

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
			return publicfiles.NewIsolated(config)
		},
		newServer: func(handler http.Handler) publicFileHTTPServer {
			return publicfiles.NewHTTPServer(handler)
		},
		notifyReady: func() error {
			supported, err := daemon.SdNotify(false, daemon.SdNotifyReady)
			if err != nil {
				return err
			}
			if !supported {
				return errors.New("systemd notification socket is unavailable")
			}
			return nil
		},
		shutdownTimeout: gracefulShutdownLimit,
		connectionLimit: maxActiveConnections,
	}
}
