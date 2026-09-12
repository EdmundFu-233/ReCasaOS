package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-ini/ini"
)

var persistMu sync.Mutex

// MigrateLegacyHTTPPort applies a legacy port to the Gateway and clears the
// one-shot migration value only after both the Gateway change and durable
// configuration write succeed. Exhausting the bounded retries returns an error
// so startup can fail before advertising readiness with an ambiguous port.
func MigrateLegacyHTTPPort(port string, attempts int, retryDelay time.Duration, change func(string) error) error {
	if port == "" {
		return nil
	}
	if attempts <= 0 || retryDelay < 0 || change == nil {
		return errors.New("invalid legacy HTTP port migration parameters")
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := change(port); err != nil {
			lastErr = fmt.Errorf("change Gateway port: %w", err)
		} else if err := PersistHTTPPort(""); err != nil {
			lastErr = err
		} else {
			return nil
		}

		if attempt < attempts && retryDelay > 0 {
			time.Sleep(retryDelay)
		}
	}

	return fmt.Errorf("legacy HTTP port migration failed after %d attempts: %w", attempts, lastErr)
}

// PersistHTTPPort updates the in-memory HTTP port and atomically persists it to
// the exact file selected by InitSetup. Failures before the atomic replacement
// restore the in-memory INI and mapped ServerInfo values. Once replacement has
// committed, the in-memory values remain aligned with the new file even if the
// final directory durability sync reports an error.
func PersistHTTPPort(value string) error {
	persistMu.Lock()
	defer persistMu.Unlock()

	if Cfg == nil {
		return errors.New("configuration is not initialized")
	}
	if ServerInfo == nil {
		return errors.New("server configuration is not initialized")
	}
	if ConfigFilePath == "" {
		return errors.New("configuration path is empty")
	}

	section := Cfg.Section("server")
	hadKey := section.HasKey("HttpPort")
	previousValue := ""
	if hadKey {
		previousValue = section.Key("HttpPort").String()
	}
	previousServerValue := ServerInfo.HttpPort

	section.Key("HttpPort").SetValue(value)
	ServerInfo.HttpPort = value
	committed, err := writeConfigAtomically(Cfg, ConfigFilePath)
	if err != nil {
		if !committed {
			if hadKey {
				section.Key("HttpPort").SetValue(previousValue)
			} else {
				section.DeleteKey("HttpPort")
			}
			ServerInfo.HttpPort = previousServerValue
		}
		return fmt.Errorf("persist HTTP port: %w", err)
	}

	return nil
}

func writeConfigAtomically(cfg *ini.File, path string) (bool, error) {
	if cfg == nil {
		return false, errors.New("configuration is nil")
	}
	if path == "" {
		return false, errors.New("configuration path is empty")
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	temporaryClosed := false
	committed := false
	defer func() {
		if !temporaryClosed {
			_ = temporary.Close()
		}
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return false, fmt.Errorf("set temporary configuration permissions: %w", err)
	}
	if _, err := cfg.WriteTo(temporary); err != nil {
		return false, fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("sync temporary configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close temporary configuration: %w", err)
	}
	temporaryClosed = true
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, fmt.Errorf("replace configuration: %w", err)
	}
	committed = true

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("open configuration directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return true, fmt.Errorf("sync configuration directory: %w", err)
	}

	return true, nil
}
