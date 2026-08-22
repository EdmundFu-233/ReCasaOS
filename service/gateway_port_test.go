package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	commonmodel "github.com/IceWhaleTech/CasaOS-Common/model"
	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/go-ini/ini"
)

type fakeGatewayPortClient struct {
	changeErr      error
	getErr         error
	getResponse    string
	changeCalls    int
	getCalls       int
	requestedPorts []string
}

func (f *fakeGatewayPortClient) ChangePort(request *commonmodel.ChangePortRequest) error {
	f.changeCalls++
	if request != nil {
		f.requestedPorts = append(f.requestedPorts, request.Port)
	}
	return f.changeErr
}

func (f *fakeGatewayPortClient) GetPort() (error, string) {
	f.getCalls++
	return f.getErr, f.getResponse
}

func TestEnsureGatewayPortConfirmsAppliedChangeAfterError(t *testing.T) {
	gateway := &fakeGatewayPortClient{
		changeErr:   errors.New("same port is already bound"),
		getResponse: `{"data":8080}`,
	}
	if err := EnsureGatewayPort(gateway, "08080"); err != nil {
		t.Fatalf("EnsureGatewayPort: %v", err)
	}
	if gateway.changeCalls != 1 || gateway.getCalls != 1 {
		t.Fatalf("Gateway calls = change:%d get:%d, want 1 and 1", gateway.changeCalls, gateway.getCalls)
	}
	if len(gateway.requestedPorts) != 1 || gateway.requestedPorts[0] != "8080" {
		t.Fatalf("normalized requested ports = %v, want [8080]", gateway.requestedPorts)
	}
}

func TestEnsureGatewayPortFailsClosedWhenStateCannotBeConfirmed(t *testing.T) {
	tests := []struct {
		name        string
		desired     string
		gateway     *fakeGatewayPortClient
		wantChanges int
		wantGets    int
	}{
		{
			name:        "invalid desired port",
			desired:     "65536",
			gateway:     &fakeGatewayPortClient{},
			wantChanges: 0,
			wantGets:    0,
		},
		{
			name:        "confirmation request failed",
			desired:     "8080",
			gateway:     &fakeGatewayPortClient{changeErr: errors.New("change failed"), getErr: errors.New("get failed")},
			wantChanges: 1,
			wantGets:    1,
		},
		{
			name:        "confirmation response malformed",
			desired:     "8080",
			gateway:     &fakeGatewayPortClient{changeErr: errors.New("change failed"), getResponse: `{"data":"not-a-port"}`},
			wantChanges: 1,
			wantGets:    1,
		},
		{
			name:        "Gateway remains on another port",
			desired:     "8080",
			gateway:     &fakeGatewayPortClient{changeErr: errors.New("change failed"), getResponse: `{"data":80}`},
			wantChanges: 1,
			wantGets:    1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := EnsureGatewayPort(test.gateway, test.desired); err == nil {
				t.Fatal("EnsureGatewayPort unexpectedly succeeded")
			}
			if test.gateway.changeCalls != test.wantChanges || test.gateway.getCalls != test.wantGets {
				t.Fatalf("Gateway calls = change:%d get:%d, want %d and %d", test.gateway.changeCalls, test.gateway.getCalls, test.wantChanges, test.wantGets)
			}
		})
	}
}

func TestLegacyHTTPPortMigrationRecoversAfterLocalCommitFailure(t *testing.T) {
	preserveGatewayMigrationConfig(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "casaos.conf")
	config.InitSetup(path, "[server]\nHttpPort = 8080\n")

	blockedPath := filepath.Join(directory, "blocked.conf")
	if err := os.Mkdir(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	config.ConfigFilePath = blockedPath
	firstGateway := &fakeGatewayPortClient{}
	err := config.MigrateLegacyHTTPPort(config.ServerInfo.HttpPort, 1, 0, func(port string) error {
		return EnsureGatewayPort(firstGateway, port)
	})
	if err == nil {
		t.Fatal("first migration unexpectedly persisted through a blocked target")
	}
	assertPersistedGatewayMigrationPort(t, path, "8080")

	// Simulate the next service process. The Gateway already applied the first
	// request, while the durable local marker still requires reconciliation.
	config.InitSetup(path, "")
	secondGateway := &fakeGatewayPortClient{
		changeErr:   errors.New("same port is already bound"),
		getResponse: `{"data":8080}`,
	}
	if err := config.MigrateLegacyHTTPPort(config.ServerInfo.HttpPort, 1, 0, func(port string) error {
		return EnsureGatewayPort(secondGateway, port)
	}); err != nil {
		t.Fatalf("replayed migration: %v", err)
	}
	if secondGateway.changeCalls != 1 || secondGateway.getCalls != 1 {
		t.Fatalf("replay calls = change:%d get:%d, want 1 and 1", secondGateway.changeCalls, secondGateway.getCalls)
	}
	assertPersistedGatewayMigrationPort(t, path, "")
}

func preserveGatewayMigrationConfig(t *testing.T) {
	t.Helper()
	oldSysInfo := *config.SysInfo
	oldAppInfo := *config.AppInfo
	oldCommonInfo := *config.CommonInfo
	oldServerInfo := *config.ServerInfo
	oldSystemConfigInfo := *config.SystemConfigInfo
	oldFileSettingInfo := *config.FileSettingInfo
	oldCfg := config.Cfg
	oldConfigFilePath := config.ConfigFilePath
	t.Cleanup(func() {
		*config.SysInfo = oldSysInfo
		*config.AppInfo = oldAppInfo
		*config.CommonInfo = oldCommonInfo
		*config.ServerInfo = oldServerInfo
		*config.SystemConfigInfo = oldSystemConfigInfo
		*config.FileSettingInfo = oldFileSettingInfo
		config.Cfg = oldCfg
		config.ConfigFilePath = oldConfigFilePath
	})
}

func assertPersistedGatewayMigrationPort(t *testing.T, path, want string) {
	t.Helper()
	persisted, err := ini.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := persisted.Section("server").Key("HttpPort").String(); got != want {
		t.Fatalf("persisted HttpPort = %q, want %q", got, want)
	}
}
