package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/labstack/echo/v4"
)

func TestPostNotifyMessageFailsClosedWithoutReadingBody(t *testing.T) {
	paths := []string{"", "arbitrary:event:name", "system_status"}
	for _, eventType := range common.EventTypes {
		paths = append(paths, eventType.Name)
	}

	for _, path := range paths {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			body := &rejectReadBody{}
			request := httptest.NewRequest(http.MethodPost, "/v1/notify/test", nil)
			request.Body = body
			request.ContentLength = maxNotifyRequestBodySize + 1
			request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			response := httptest.NewRecorder()
			ctx := echo.New().NewContext(request, response)
			ctx.SetPath("/v1/notify/:path")
			ctx.SetParamNames("path")
			ctx.SetParamValues(path)

			if err := PostNotifyMessage(ctx); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusGone {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			assertResultMessage(t, response, notifyIngressDisabledMessage)
			if got := body.reads.Load(); got != 0 {
				t.Fatalf("retired ingress read body %d times", got)
			}
		})
	}
}

func TestSystemStatusBodyLimitForFixedAndChunkedRequests(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		transferName := "fixed"
		if chunked {
			transferName = "chunked"
		}
		for _, test := range []struct {
			name        string
			size        int
			wantStatus  int
			wantPatched bool
			wantMessage string
		}{
			{name: "at limit", size: int(maxNotifyRequestBodySize), wantStatus: http.StatusOK, wantPatched: true},
			{name: "limit plus one", size: int(maxNotifyRequestBodySize) + 1, wantStatus: http.StatusRequestEntityTooLarge, wantMessage: notifyPayloadTooLargeMessage},
		} {
			t.Run(transferName+"/"+test.name, func(t *testing.T) {
				body := sizedSystemStatusObject(t, test.size)
				patched := false
				response, err := runSystemStatusHandler(body, chunked, []string{echo.MIMEApplicationJSON}, func(map[string]interface{}) {
					patched = true
				})
				if err != nil {
					t.Fatal(err)
				}
				if response.Code != test.wantStatus {
					t.Fatalf("status = %d, want %d, body = %s", response.Code, test.wantStatus, response.Body.String())
				}
				if patched != test.wantPatched {
					t.Fatalf("patch called = %v, want %v", patched, test.wantPatched)
				}
				if test.wantMessage != "" {
					assertResultMessage(t, response, test.wantMessage)
				}
			})
		}
	}
}

func TestSystemStatusBodyLimitIncludesTrailingWhitespace(t *testing.T) {
	body := sizedSystemStatusObject(t, int(maxNotifyRequestBodySize)) + " "
	if len(body) != int(maxNotifyRequestBodySize)+1 {
		t.Fatalf("payload length = %d", len(body))
	}
	for _, chunked := range []bool{false, true} {
		name := "fixed"
		if chunked {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			patched := false
			response, err := runSystemStatusHandler(body, chunked, []string{echo.MIMEApplicationJSON}, func(map[string]interface{}) {
				patched = true
			})
			if err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			assertResultMessage(t, response, notifyPayloadTooLargeMessage)
			if patched {
				t.Fatal("over-limit payload with trailing whitespace was applied")
			}
		})
	}
}

func TestSystemStatusRequiresOneNonNullJSONObject(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		contentTypes []string
		wantStatus   int
		wantMessage  string
		wantPatched  bool
	}{
		{name: "json with charset", body: `{"sys_disk":{}}`, contentTypes: []string{"application/json; charset=utf-8"}, wantStatus: http.StatusOK, wantPatched: true},
		{name: "missing content type", body: `{"sys_disk":{}}`, wantStatus: http.StatusUnsupportedMediaType, wantMessage: notifyUnsupportedMediaTypeMessage},
		{name: "wrong content type", body: `{"sys_disk":{}}`, contentTypes: []string{echo.MIMETextPlain}, wantStatus: http.StatusUnsupportedMediaType, wantMessage: notifyUnsupportedMediaTypeMessage},
		{name: "repeated content type", body: `{"sys_disk":{}}`, contentTypes: []string{echo.MIMEApplicationJSON, echo.MIMEApplicationJSON}, wantStatus: http.StatusUnsupportedMediaType, wantMessage: notifyUnsupportedMediaTypeMessage},
		{name: "null", body: `null`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "array", body: `[]`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "scalar", body: `true`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "empty object", body: `{}`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "empty body", body: ``, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "malformed", body: `{"secret-marker":`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "trailing object", body: `{"sys_disk":{}} {"secret-marker":true}`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
		{name: "trailing scalar", body: `{"sys_disk":{}} true`, contentTypes: []string{echo.MIMEApplicationJSON}, wantStatus: http.StatusBadRequest, wantMessage: notifyInvalidPayloadMessage},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patched := false
			response, err := runSystemStatusHandler(test.body, false, test.contentTypes, func(map[string]interface{}) {
				patched = true
			})
			if err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if patched != test.wantPatched {
				t.Fatalf("patch called = %v, want %v", patched, test.wantPatched)
			}
			if test.wantMessage != "" {
				assertResultMessage(t, response, test.wantMessage)
			}
			if strings.Contains(response.Body.String(), "secret-marker") || strings.Contains(response.Body.String(), "invalid character") {
				t.Fatalf("response exposed decoder or payload detail: %s", response.Body.String())
			}
		})
	}
}

func TestSystemStatusRejectsInvalidUTF8WithoutMutation(t *testing.T) {
	payload := `{"sys_disk":{"name":"` + string([]byte{0xff}) + `"}}`
	patched := false
	response, err := runSystemStatusHandler(payload, false, []string{echo.MIMEApplicationJSON}, func(map[string]interface{}) {
		patched = true
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertResultMessage(t, response, notifyInvalidPayloadMessage)
	if patched {
		t.Fatal("invalid UTF-8 payload mutated retained state")
	}
}

func TestSystemStatusPreservesRawNumberAndFutureSchema(t *testing.T) {
	var patched map[string]interface{}
	response, err := runSystemStatusHandler(`{"sys_disk":{"large":9007199254740993,"future":[true,null]}}`, false, []string{echo.MIMEApplicationJSON}, func(message map[string]interface{}) {
		patched = message
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	disk, ok := patched["sys_disk"].(json.RawMessage)
	if !ok {
		t.Fatalf("sys_disk type = %T, want json.RawMessage", patched["sys_disk"])
	}
	want := `{"large":9007199254740993,"future":[true,null]}`
	if string(disk) != want {
		t.Fatalf("sys_disk raw JSON = %s, want %s", disk, want)
	}
	assertJSONValue(t, patched, "sys_disk", want)
}

func TestSystemStatusPatchRetainsAbsentFieldsAndRejectsUnknownAtomically(t *testing.T) {
	var state sync.Map
	var applied atomic.Int64
	patch := func(message map[string]interface{}) {
		applied.Add(1)
		for name, value := range message {
			state.Store(name, value)
		}
	}

	invokeSystemStatus(t, `{"sys_disk":{"generation":1}}`, patch, http.StatusOK, "")
	invokeSystemStatus(t, `{"sys_usb":[{"name":"first"}]}`, patch, http.StatusOK, "")
	assertStoredJSONValue(t, &state, "sys_disk", `{"generation":1}`)
	assertStoredJSONValue(t, &state, "sys_usb", `[{"name":"first"}]`)

	invokeSystemStatus(t, `{"sys_disk":{"generation":2}}`, patch, http.StatusOK, "")
	assertStoredJSONValue(t, &state, "sys_disk", `{"generation":2}`)
	assertStoredJSONValue(t, &state, "sys_usb", `[{"name":"first"}]`)

	before := applied.Load()
	invokeSystemStatus(t, `{"sys_disk":{"generation":3},"unknown":{"secret-marker":true}}`, patch, http.StatusBadRequest, notifyUnsupportedSystemFieldMessage)
	if got := applied.Load(); got != before {
		t.Fatalf("mixed unknown patch applied %d times, want %d", got, before)
	}
	assertStoredJSONValue(t, &state, "sys_disk", `{"generation":2}`)

	invokeSystemStatus(t, `{"sys_usb":[]}`, patch, http.StatusOK, "")
	assertStoredJSONValue(t, &state, "sys_usb", `[]`)
	assertSystemStatusCardinality(t, &state, 2)
}

func TestSystemStatusUnknownKeysCannotGrowRetainedState(t *testing.T) {
	var state sync.Map
	patch := func(message map[string]interface{}) {
		for name, value := range message {
			state.Store(name, value)
		}
	}

	invokeSystemStatus(t, `{"sys_disk":{}}`, patch, http.StatusOK, "")
	invokeSystemStatus(t, `{"sys_usb":[]}`, patch, http.StatusOK, "")
	for index := 0; index < 1_000; index++ {
		body := fmt.Sprintf(`{"unknown_%d":true}`, index)
		invokeSystemStatus(t, body, patch, http.StatusBadRequest, notifyUnsupportedSystemFieldMessage)
	}
	assertSystemStatusCardinality(t, &state, 2)
}

func TestSystemStatusConcurrentPatchesRemainBounded(t *testing.T) {
	var state sync.Map
	patch := func(message map[string]interface{}) {
		for name, value := range message {
			state.Store(name, value)
		}
	}

	done := make(chan struct{})
	readerDone := make(chan struct{})
	readerErrors := make(chan error, 1)
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-done:
				return
			default:
				count := 0
				invalid := ""
				state.Range(func(key, value interface{}) bool {
					name, ok := key.(string)
					if !ok {
						invalid = fmt.Sprintf("non-string key %T", key)
						return false
					}
					if !isAllowedSystemStatusField(name) {
						invalid = "unexpected key " + name
						return false
					}
					if _, err := json.Marshal(value); err != nil {
						invalid = fmt.Sprintf("marshal %s: %v", name, err)
						return false
					}
					count++
					return count <= maxSystemStatusFields
				})
				if invalid != "" || count > maxSystemStatusFields {
					select {
					case readerErrors <- fmt.Errorf("state invalid: %s, count %d", invalid, count):
					default:
					}
					return
				}
			}
		}
	}()

	workerErrors := make(chan error, 16)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 50; iteration++ {
				body := fmt.Sprintf(`{"sys_disk":{"worker":%d,"iteration":%d}}`, worker, iteration)
				if (worker+iteration)%2 == 1 {
					body = fmt.Sprintf(`{"sys_usb":[{"worker":%d,"iteration":%d}]}`, worker, iteration)
				}
				response, err := runSystemStatusHandler(body, false, []string{echo.MIMEApplicationJSON}, patch)
				if err != nil {
					workerErrors <- err
					return
				}
				if response.Code != http.StatusOK {
					workerErrors <- fmt.Errorf("status = %d, body = %s", response.Code, response.Body.String())
					return
				}
			}
		}()
	}
	workers.Wait()
	close(done)
	<-readerDone

	select {
	case err := <-workerErrors:
		t.Fatal(err)
	default:
	}
	select {
	case err := <-readerErrors:
		t.Fatal(err)
	default:
	}
	assertSystemStatusCardinality(t, &state, 2)
}

type rejectReadBody struct {
	reads atomic.Int64
}

func (b *rejectReadBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, errors.New("request body must not be read")
}

func (*rejectReadBody) Close() error { return nil }

type notifyReaderOnly struct {
	io.Reader
}

func runSystemStatusHandler(body string, chunked bool, contentTypes []string, patch func(map[string]interface{})) (*httptest.ResponseRecorder, error) {
	var reader io.Reader = strings.NewReader(body)
	if chunked {
		reader = notifyReaderOnly{Reader: reader}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/notify/system_status", reader)
	if chunked {
		request.ContentLength = -1
		request.TransferEncoding = []string{"chunked"}
	}
	for _, contentType := range contentTypes {
		request.Header.Add(echo.HeaderContentType, contentType)
	}
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	return response, postSystemStatusNotify(ctx, patch)
}

func invokeSystemStatus(t *testing.T, body string, patch func(map[string]interface{}), wantStatus int, wantMessage string) {
	t.Helper()
	response, err := runSystemStatusHandler(body, false, []string{echo.MIMEApplicationJSON}, patch)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != wantStatus {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, wantStatus, response.Body.String())
	}
	if wantMessage != "" {
		assertResultMessage(t, response, wantMessage)
	}
	if strings.Contains(response.Body.String(), "secret-marker") {
		t.Fatalf("response exposed payload detail: %s", response.Body.String())
	}
}

func sizedSystemStatusObject(t *testing.T, size int) string {
	t.Helper()
	prefix := `{"sys_disk":{"padding":"`
	suffix := `"}}`
	if size < len(prefix)+len(suffix) {
		t.Fatalf("requested JSON size %d is too small", size)
	}
	body := prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
	if len(body) != size {
		t.Fatalf("sized JSON length = %d, want %d", len(body), size)
	}
	return body
}

func assertResultMessage(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var result struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
	if result.Message != want {
		t.Fatalf("message = %q, want %q", result.Message, want)
	}
}

func assertJSONValue(t *testing.T, message map[string]interface{}, name, want string) {
	t.Helper()
	value, ok := message[name]
	if !ok {
		t.Fatalf("message missing %q: %#v", name, message)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal message[%q]: %v", name, err)
	}
	if string(encoded) != want {
		t.Fatalf("message[%q] = %s, want %s", name, encoded, want)
	}
}

func assertStoredJSONValue(t *testing.T, state *sync.Map, name, want string) {
	t.Helper()
	value, ok := state.Load(name)
	if !ok {
		t.Fatalf("state missing %q", name)
	}
	assertJSONValue(t, map[string]interface{}{name: value}, name, want)
}

func assertSystemStatusCardinality(t *testing.T, state *sync.Map, want int) {
	t.Helper()
	count := 0
	state.Range(func(key, _ interface{}) bool {
		name, ok := key.(string)
		if !ok {
			t.Fatalf("state key type = %T, want string", key)
		}
		if !isAllowedSystemStatusField(name) {
			t.Fatalf("unexpected retained key %q", name)
		}
		count++
		return true
	})
	if count != want {
		t.Fatalf("retained key count = %d, want %d", count, want)
	}
}
