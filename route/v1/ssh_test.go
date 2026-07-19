package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/labstack/echo/v4"
)

func TestValidateSSHParameters(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		password  string
		port      string
		wantError bool
	}{
		{name: "valid", username: "admin", password: "secret", port: "22"},
		{name: "empty username", password: "secret", port: "22", wantError: true},
		{name: "empty password", username: "admin", port: "22", wantError: true},
		{name: "zero port", username: "admin", password: "secret", port: "0", wantError: true},
		{name: "large port", username: "admin", password: "secret", port: "65536", wantError: true},
		{name: "non canonical port", username: "admin", password: "secret", port: "022", wantError: true},
		{name: "nul password", username: "admin", password: "bad\x00secret", port: "22", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSSHParameters(test.username, test.password, test.port)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestBoundedTerminalDimension(t *testing.T) {
	for _, test := range []struct {
		value int
		want  int
	}{
		{value: 80, want: 80},
		{value: 0, want: 32},
		{value: 1001, want: 32},
	} {
		if got := boundedTerminalDimension(test.value, 32); got != test.want {
			t.Errorf("boundedTerminalDimension(%d) = %d, want %d", test.value, got, test.want)
		}
	}
}

func TestParseSSHWebSocketHandshake(t *testing.T) {
	handshake, err := parseSSHWebSocketHandshake([]byte(`{"username":"admin","password":"secret","port":"22","cols":80,"rows":24}`))
	if err != nil {
		t.Fatal(err)
	}
	if handshake.Username != "admin" || handshake.Password != "secret" || handshake.Port != "22" {
		t.Fatalf("unexpected handshake: %#v", handshake)
	}

	for _, payload := range []string{
		`{"username":"admin","password":"","port":"22"}`,
		`{"username":"admin","password":"secret","port":"022"}`,
		`{"username":"admin","password":"secret","port":"22","token":"unexpected"}`,
		`{"username":"admin","password":"secret","port":"22"} {}`,
		`[]`,
	} {
		if _, err := parseSSHWebSocketHandshake([]byte(payload)); err == nil {
			t.Errorf("payload %s unexpectedly accepted", payload)
		}
	}
}

func TestSSHTicketIsBoundAndSingleUse(t *testing.T) {
	registry := sshTicketRegistry{tickets: make(map[string]sshTicket)}
	handshake := sshWebSocketHandshake{Username: "admin", Password: "secret", Port: "22"}
	issuer := newSSHTicketTestContext("ReCasaOS browser", 7, "admin")
	value, err := registry.issue(issuer, handshake)
	if err != nil {
		t.Fatal(err)
	}

	consumer := newSSHTicketTestContext("ReCasaOS browser", 7, "admin")
	consumer.Request().AddCookie(&http.Cookie{Name: sshTicketCookieName, Value: value})
	got, ok := registry.consume(consumer)
	if !ok || got.Username != handshake.Username || got.Password != handshake.Password || got.Port != handshake.Port {
		t.Fatalf("ticket consume = (%#v, %v)", got, ok)
	}
	if _, ok := registry.consume(consumer); ok {
		t.Fatal("one-use SSH ticket was accepted twice")
	}
}

func TestSSHTicketRejectsDifferentPrincipalAgentAndDuplicates(t *testing.T) {
	for _, test := range []struct {
		name      string
		userAgent string
		userID    int
		username  string
		duplicate bool
	}{
		{name: "different agent", userAgent: "other", userID: 7, username: "admin"},
		{name: "different user", userAgent: "ReCasaOS browser", userID: 8, username: "other"},
		{name: "duplicate cookie", userAgent: "ReCasaOS browser", userID: 7, username: "admin", duplicate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := sshTicketRegistry{tickets: make(map[string]sshTicket)}
			issuer := newSSHTicketTestContext("ReCasaOS browser", 7, "admin")
			value, err := registry.issue(issuer, sshWebSocketHandshake{Username: "admin", Password: "secret", Port: "22"})
			if err != nil {
				t.Fatal(err)
			}
			consumer := newSSHTicketTestContext(test.userAgent, test.userID, test.username)
			consumer.Request().AddCookie(&http.Cookie{Name: sshTicketCookieName, Value: value})
			if test.duplicate {
				consumer.Request().AddCookie(&http.Cookie{Name: sshTicketCookieName, Value: value})
			}
			if _, ok := registry.consume(consumer); ok {
				t.Fatal("mismatched or duplicate SSH ticket was accepted")
			}
		})
	}
}

func newSSHTicketTestContext(userAgent string, userID int, username string) echo.Context {
	request := httptest.NewRequest(http.MethodGet, "/v1/sys/wsssh", nil)
	request.Header.Set("User-Agent", userAgent)
	ctx := echo.New().NewContext(request, httptest.NewRecorder())
	ctx.Set("user", &commonjwt.Claims{ID: userID, Username: username})
	return ctx
}
