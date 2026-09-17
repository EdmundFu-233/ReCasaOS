package config

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
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

// writeConfigAtomically serializes cfg and publishes it with the
// descriptor-pinned atomic replacement in pkg/filesecurity. The destination
// must be an absolute, clean path whose parent is a real directory: a
// relative path or a symlinked parent fails closed without writing. The
// commit report stays meaningful: serialization and every staging step
// return committed == false with the destination untouched, while a failure
// of the final directory durability sync returns committed == true.
func writeConfigAtomically(cfg *ini.File, path string) (bool, error) {
	if cfg == nil {
		return false, errors.New("configuration is nil")
	}
	if path == "" {
		return false, errors.New("configuration path is empty")
	}

	var serialized bytes.Buffer
	if _, err := cfg.WriteTo(&serialized); err != nil {
		return false, fmt.Errorf("serialize configuration: %w", err)
	}
	published, err := filesecurity.ReplaceRegularFileWithCommit(path, serialized.Bytes(), 0o600)
	if err != nil {
		return published, fmt.Errorf("replace configuration: %w", err)
	}
	return true, nil
}
