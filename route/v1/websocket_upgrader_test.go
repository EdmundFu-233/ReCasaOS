package v1

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

func TestReviewedGorillaWebSocketUpgraders(t *testing.T) {
	tests := []struct {
		name     string
		upgrader websocket.Upgrader
	}{
		{name: "ssh", upgrader: upgrader},
		{name: "file", upgrader: upgraderFile},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("missing upgrade headers", func(t *testing.T) {
				e := echo.New()
				request := httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
				request.Header.Set("Connection", "upgrade")
				request.Header.Set("Sec-WebSocket-Version", "13")
				response := httptest.NewRecorder()
				ctx := e.NewContext(request, response)

				if _, err := test.upgrader.Upgrade(ctx.Response().Writer, ctx.Request(), nil); err == nil {
					t.Fatal("request missing Upgrade token unexpectedly upgraded")
				}
				if response.Code != http.StatusUpgradeRequired {
					t.Fatalf("status = %d, want %d", response.Code, http.StatusUpgradeRequired)
				}
				if got := response.Header().Get("Upgrade"); !strings.EqualFold(got, "websocket") {
					t.Fatalf("Upgrade header = %q, want websocket", got)
				}
			})

			t.Run("echo response controller handshake", func(t *testing.T) {
				e := echo.New()
				serverDone := make(chan error, 1)
				e.GET("/ws", func(ctx echo.Context) error {
					conn, err := test.upgrader.Upgrade(ctx.Response().Writer, ctx.Request(), nil)
					if err != nil {
						serverDone <- fmt.Errorf("upgrade: %w", err)
						return nil
					}
					defer conn.Close()

					messageType, payload, err := conn.ReadMessage()
					if err != nil {
						serverDone <- fmt.Errorf("read: %w", err)
						return nil
					}
					if err := conn.WriteMessage(messageType, payload); err != nil {
						serverDone <- fmt.Errorf("write: %w", err)
						return nil
					}
					serverDone <- nil
					return nil
				})

				server := httptest.NewServer(e)
				defer server.Close()

				dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
				headers := http.Header{"Origin": []string{server.URL}}
				wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
				conn, response, err := dialer.Dial(wsURL, headers)
				if err != nil {
					if response != nil && response.Body != nil {
						response.Body.Close()
					}
					t.Fatalf("dial: %v", err)
				}
				defer conn.Close()
				if response == nil {
					t.Fatal("successful dial returned no handshake response")
				}
				if response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("handshake status = %d, want %d", response.StatusCode, http.StatusSwitchingProtocols)
				}

				deadline := time.Now().Add(5 * time.Second)
				if err := conn.SetWriteDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := conn.SetReadDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				payload := []byte("recasaos-websocket-probe")
				if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
					t.Fatalf("write probe: %v", err)
				}
				messageType, echoed, err := conn.ReadMessage()
				if err != nil {
					t.Fatalf("read probe: %v", err)
				}
				if messageType != websocket.TextMessage || string(echoed) != string(payload) {
					t.Fatalf("echo = type %d payload %q", messageType, echoed)
				}

				select {
				case err := <-serverDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("server handler did not finish")
				}
			})
		})
	}
}
