package v1

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/common_err"
	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/sshsecurity"
	"github.com/labstack/echo/v4"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	modelCommon "github.com/IceWhaleTech/CasaOS-Common/model"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	CheckOrigin:      httpsecurity.WebSocketOriginAllowed,
	HandshakeTimeout: time.Duration(time.Second * 5),
}

const (
	sshHandshakeTimeout     = 10 * time.Second
	sshTicketLifetime       = 30 * time.Second
	sshTicketCookieName     = "recasaos_ssh_ticket"
	maxPendingSSHTickets    = 64
	sshWebSocketWriteWait   = 10 * time.Second
	sshWebSocketMaxLifetime = 12 * time.Hour
	sshOutputChunkSize      = 32 << 10
)

var sshWebSocketSlots = make(chan struct{}, 16)

type sshWebSocketHandshake struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Port     string `json:"port"`
	Cols     int    `json:"cols"`
	Rows     int    `json:"rows"`
}

type sshTicket struct {
	username  string
	password  []byte
	port      string
	principal string
	userAgent string
	expires   time.Time
}

type sshTicketRegistry struct {
	mu      sync.Mutex
	tickets map[string]sshTicket
}

var pendingSSHTickets = sshTicketRegistry{tickets: make(map[string]sshTicket)}

func PostSshLogin(ctx echo.Context) error {
	j := make(map[string]string)
	if err := ctx.Bind(&j); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, modelCommon.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	userName := j["username"]
	password := j["password"]
	port := j["port"]
	if err := validateSSHParameters(userName, password, port); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, modelCommon.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: "Username or password or port is empty"})
	}
	client, err := sshsecurity.DialLocalContext(ctx.Request().Context(), userName, password, port)
	if err != nil {
		if errors.Is(err, sshsecurity.ErrLocalSSHBusy) {
			return ctx.JSON(http.StatusTooManyRequests, modelCommon.Result{Success: http.StatusTooManyRequests, Message: "too many concurrent SSH login attempts"})
		}
		logger.Error("connect ssh error", zap.Any("error", err))
		return ctx.JSON(common_err.CLIENT_ERROR, modelCommon.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: "Please check if the username and port are correct, and make sure that ssh server is installed."})
	}
	defer client.Close()
	ticket, err := pendingSSHTickets.issue(ctx, sshWebSocketHandshake{Username: userName, Password: password, Port: port})
	if err != nil {
		return ctx.JSON(http.StatusTooManyRequests, modelCommon.Result{Success: http.StatusTooManyRequests, Message: "too many pending SSH logins"})
	}
	ctx.SetCookie(&http.Cookie{
		Name:     sshTicketCookieName,
		Value:    ticket,
		Path:     "/v1/sys/wsssh",
		Expires:  time.Now().Add(sshTicketLifetime),
		MaxAge:   int(sshTicketLifetime.Seconds()),
		HttpOnly: true,
		Secure:   secureSSHTicketCookie(ctx.Request()),
		SameSite: http.SameSiteStrictMode,
	})
	return ctx.JSON(common_err.SUCCESS, modelCommon.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

func WsSsh(ctx echo.Context) error {
	// The shipped CasaOS UI performs an authenticated POST before opening the
	// WebSocket, but still repeats credentials in its URL. ReCasaOS ignores
	// those URL values and consumes the POST-issued, one-use cookie ticket.
	// New clients may omit both and send credentials in the first text frame.
	handshake, ticketOK := pendingSSHTickets.consume(ctx)
	legacyQuery := ctx.QueryParam("username") != "" || ctx.QueryParam("password") != "" || ctx.QueryParam("port") != ""
	if legacyQuery && !ticketOK {
		return ctx.JSON(http.StatusUnauthorized, modelCommon.Result{Success: http.StatusUnauthorized, Message: "SSH login ticket is missing or expired"})
	}
	select {
	case sshWebSocketSlots <- struct{}{}:
		defer func() { <-sshWebSocketSlots }()
	default:
		return ctx.JSON(http.StatusTooManyRequests, modelCommon.Result{Success: http.StatusTooManyRequests, Message: "too many active SSH WebSocket connections"})
	}

	upgradeHeaders := http.Header{}
	if ticketOK {
		upgradeHeaders.Add("Set-Cookie", (&http.Cookie{Name: sshTicketCookieName, Path: "/v1/sys/wsssh", MaxAge: -1, HttpOnly: true, Secure: secureSSHTicketCookie(ctx.Request()), SameSite: http.SameSiteStrictMode}).String())
	}
	wsConn, err := upgrader.Upgrade(ctx.Response().Writer, ctx.Request(), upgradeHeaders)
	if err != nil {
		return nil
	}
	defer wsConn.Close()
	wsConn.SetReadLimit(64 << 10)

	if !ticketOK {
		handshake, err = readSSHWebSocketHandshake(wsConn)
		if err != nil {
			writeSSHClose(wsConn, websocket.ClosePolicyViolation, "invalid SSH handshake")
			return nil
		}
	}
	cols := boundedTerminalDimension(handshake.Cols, 200)
	rows := boundedTerminalDimension(handshake.Rows, 32)

	client, err := sshsecurity.DialLocalContext(ctx.Request().Context(), handshake.Username, handshake.Password, handshake.Port)
	if err != nil {
		if errors.Is(err, sshsecurity.ErrLocalSSHBusy) {
			writeSSHClose(wsConn, websocket.CloseTryAgainLater, "SSH service is busy")
			return nil
		}
		logger.Error("connect ssh websocket error", zap.Error(err))
		writeSSHClose(wsConn, websocket.ClosePolicyViolation, "SSH authentication failed")
		return nil
	}
	defer client.Close()

	if err := runSSHWebSocketSession(wsConn, client, cols, rows); err != nil {
		logger.Error("SSH WebSocket session ended", zap.Error(err))
	}
	return nil
}

func runSSHWebSocketSession(wsConn *websocket.Conn, client *ssh.Client, cols, rows int) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm", rows, cols, modes); err != nil {
		return err
	}
	if err := session.Shell(); err != nil {
		return err
	}

	done := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(done) }) }
	output := make(chan []byte, 16)
	go copySSHOutput(stdout, output, done)
	go copySSHOutput(stderr, output, done)
	go writeSSHWebSocketOutput(wsConn, output, done, stop)
	go readSSHWebSocketInput(wsConn, session, stdin, stop)
	go func() {
		_ = session.Wait()
		stop()
	}()

	lifetime := time.NewTimer(sshWebSocketMaxLifetime)
	defer lifetime.Stop()
	select {
	case <-done:
		return nil
	case <-lifetime.C:
		stop()
		return errors.New("SSH WebSocket maximum lifetime reached")
	}
}

func copySSHOutput(source io.Reader, output chan<- []byte, done <-chan struct{}) {
	buffer := make([]byte, sshOutputChunkSize)
	for {
		count, err := source.Read(buffer)
		if count > 0 {
			chunk := append([]byte(nil), buffer[:count]...)
			select {
			case output <- chunk:
			case <-done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeSSHWebSocketOutput(wsConn *websocket.Conn, output <-chan []byte, done <-chan struct{}, stop func()) {
	for {
		select {
		case <-done:
			return
		case chunk := <-output:
			if err := wsConn.SetWriteDeadline(time.Now().Add(sshWebSocketWriteWait)); err != nil {
				stop()
				return
			}
			if err := wsConn.WriteMessage(websocket.TextMessage, chunk); err != nil {
				stop()
				return
			}
		}
	}
}

func readSSHWebSocketInput(wsConn *websocket.Conn, session *ssh.Session, stdin io.Writer, stop func()) {
	defer stop()
	for {
		messageType, payload, err := wsConn.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		var message struct {
			Type string `json:"type"`
			Cmd  string `json:"cmd"`
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
		}
		if err := json.Unmarshal(payload, &message); err != nil {
			message.Type = "cmd"
			message.Cmd = string(payload)
		}
		switch message.Type {
		case "resize":
			if message.Cols >= 1 && message.Cols <= 1000 && message.Rows >= 1 && message.Rows <= 1000 {
				_ = session.WindowChange(message.Rows, message.Cols)
			}
		case "cmd":
			if len(message.Cmd) <= 64<<10 {
				if _, err := io.WriteString(stdin, message.Cmd); err != nil {
					return
				}
			}
		}
	}
}

func secureSSHTicketCookie(request *http.Request) bool {
	if request != nil && request.TLS != nil {
		return true
	}
	if request == nil {
		return false
	}
	origin, ok := httpsecurity.NormalizeOrigin(request.Header.Get("Origin"))
	return ok && strings.HasPrefix(origin, "https://")
}

func (r *sshTicketRegistry) issue(ctx echo.Context, handshake sshWebSocketHandshake) (string, error) {
	principal, ok := sshPrincipal(ctx)
	if !ok {
		return "", echo.ErrUnauthorized
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(random)
	now := time.Now()

	r.mu.Lock()
	r.cleanupLocked(now)
	if len(r.tickets) >= maxPendingSSHTickets {
		r.mu.Unlock()
		return "", errors.New("too many pending SSH tickets")
	}
	expires := now.Add(sshTicketLifetime)
	r.tickets[value] = sshTicket{
		username:  handshake.Username,
		password:  append([]byte(nil), handshake.Password...),
		port:      handshake.Port,
		principal: principal,
		userAgent: ctx.Request().UserAgent(),
		expires:   expires,
	}
	r.mu.Unlock()
	time.AfterFunc(sshTicketLifetime, func() { r.expire(value, expires) })
	return value, nil
}

func (r *sshTicketRegistry) consume(ctx echo.Context) (sshWebSocketHandshake, bool) {
	var empty sshWebSocketHandshake
	principal, ok := sshPrincipal(ctx)
	if !ok {
		return empty, false
	}
	var value string
	count := 0
	for _, cookie := range ctx.Request().Cookies() {
		if cookie.Name == sshTicketCookieName {
			value = cookie.Value
			count++
		}
	}
	if count != 1 || len(value) != 43 {
		return empty, false
	}

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked(now)
	ticket, exists := r.tickets[value]
	if exists {
		delete(r.tickets, value)
	}
	if !exists || !now.Before(ticket.expires) || ticket.principal != principal || ticket.userAgent != ctx.Request().UserAgent() {
		wipeBytes(ticket.password)
		return empty, false
	}
	handshake := sshWebSocketHandshake{Username: ticket.username, Password: string(ticket.password), Port: ticket.port}
	wipeBytes(ticket.password)
	return handshake, true
}

func (r *sshTicketRegistry) cleanupLocked(now time.Time) {
	for value, ticket := range r.tickets {
		if !now.Before(ticket.expires) {
			wipeBytes(ticket.password)
			delete(r.tickets, value)
		}
	}
}

func (r *sshTicketRegistry) expire(value string, expires time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ticket, exists := r.tickets[value]
	if exists && ticket.expires.Equal(expires) {
		wipeBytes(ticket.password)
		delete(r.tickets, value)
	}
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func sshPrincipal(ctx echo.Context) (string, bool) {
	claims, ok := ctx.Get("user").(*commonjwt.Claims)
	if !ok || claims == nil || claims.ID < 1 || strings.TrimSpace(claims.Username) == "" {
		return "", false
	}
	return fmt.Sprintf("%d:%s", claims.ID, claims.Username), true
}

func readSSHWebSocketHandshake(conn *websocket.Conn) (sshWebSocketHandshake, error) {
	var handshake sshWebSocketHandshake
	if err := conn.SetReadDeadline(time.Now().Add(sshHandshakeTimeout)); err != nil {
		return handshake, err
	}
	defer conn.SetReadDeadline(time.Time{})

	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return handshake, err
	}
	if messageType != websocket.TextMessage {
		return handshake, echo.ErrBadRequest
	}
	return parseSSHWebSocketHandshake(payload)
}

func parseSSHWebSocketHandshake(payload []byte) (sshWebSocketHandshake, error) {
	var handshake sshWebSocketHandshake
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&handshake); err != nil {
		return handshake, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return handshake, echo.ErrBadRequest
	}
	if err := validateSSHParameters(handshake.Username, handshake.Password, handshake.Port); err != nil {
		return handshake, err
	}
	return handshake, nil
}

func writeSSHClose(conn *websocket.Conn, code int, message string) {
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, message), time.Now().Add(time.Second))
}

func validateSSHParameters(username, password, port string) error {
	if strings.TrimSpace(username) == "" || password == "" || len(username) > 128 || len(password) > 4096 || strings.IndexByte(username, 0) >= 0 || strings.IndexByte(password, 0) >= 0 {
		return echo.ErrBadRequest
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 || strconv.Itoa(parsedPort) != port {
		return echo.ErrBadRequest
	}
	return nil
}

func boundedTerminalDimension(dimension, fallback int) int {
	if dimension < 1 || dimension > 1000 {
		return fallback
	}
	return dimension
}
