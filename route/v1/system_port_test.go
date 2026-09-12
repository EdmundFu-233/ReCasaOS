package v1

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestGetPortRejectsUnknownProtocolBeforeProbing(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/port/?type=icmp", nil)
	response := httptest.NewRecorder()

	if err := GetPort(echo.New().NewContext(request, response)); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestFindAvailablePortStopsAfterFiniteAttempts(t *testing.T) {
	getCalls := 0
	availableCalls := 0
	_, err := findAvailablePort(
		"tcp",
		3,
		func(string) (int, error) {
			getCalls++
			return 32000 + getCalls, nil
		},
		func(int, string) bool {
			availableCalls++
			return false
		},
	)
	if !errors.Is(err, errAvailablePortProbeExhausted) {
		t.Fatalf("error = %v, want exhaustion", err)
	}
	if getCalls != 3 || availableCalls != 3 {
		t.Fatalf("probe calls = (%d, %d), want (3, 3)", getCalls, availableCalls)
	}
}

func TestFindAvailablePortAcceptsOnlyValidatedCandidate(t *testing.T) {
	candidates := []int{0, 65536, 42000}
	index := 0
	port, err := findAvailablePort(
		"udp",
		len(candidates),
		func(string) (int, error) {
			candidate := candidates[index]
			index++
			return candidate, nil
		},
		func(candidate int, protocol string) bool {
			if protocol != "udp" {
				t.Fatalf("protocol = %q, want udp", protocol)
			}
			return candidate == 42000
		},
	)
	if err != nil || port != 42000 {
		t.Fatalf("findAvailablePort() = %d, %v; want 42000", port, err)
	}
}

func TestPortCheckRejectsInvalidProtocolAndPort(t *testing.T) {
	for _, target := range []string{
		"/v1/port/state/22?type=icmp",
		"/v1/port/state/0",
		"/v1/port/state/01",
		"/v1/port/state/65536",
		"/v1/port/state/not-a-port",
	} {
		t.Run(target, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			response := httptest.NewRecorder()
			if err := PortCheck(echo.New().NewContext(request, response)); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestParseCanonicalPort(t *testing.T) {
	for _, value := range []string{"", "0", "01", "+22", "65536", "port"} {
		if port, err := parseCanonicalPort(value); err == nil {
			t.Fatalf("parseCanonicalPort(%q) = %d, want error", value, port)
		}
	}
	if port, err := parseCanonicalPort("22"); err != nil || port != 22 {
		t.Fatalf("parseCanonicalPort(22) = %d, %v", port, err)
	}
}
