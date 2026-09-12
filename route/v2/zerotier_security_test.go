package v2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/internal/zerotierapi"
	"github.com/labstack/echo/v4"
)

func newZeroTierInfoTestContext(parent context.Context) (echo.Context, *httptest.ResponseRecorder) {
	logger.LogInitConsoleOnly()
	request := httptest.NewRequest(http.MethodGet, "http://recasaos.test/v2/zt/info", nil)
	if parent != nil {
		request = request.WithContext(parent)
	}
	recorder := httptest.NewRecorder()
	return echo.New().NewContext(request, recorder), recorder
}

func TestGetZeroTierInfoUsesOneBoundedContextForTheTraversal(t *testing.T) {
	ctx, recorder := newZeroTierInfoTestContext(context.Background())
	var firstDeadline time.Time
	calls := 0
	getter := func(ctx context.Context, endpoint string) ([]byte, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
			t.Fatalf("unexpected deadline %v, %t", deadline, ok)
		}
		if firstDeadline.IsZero() {
			firstDeadline = deadline
		} else if !deadline.Equal(firstDeadline) {
			t.Fatalf("per-call deadline was reset: %v != %v", deadline, firstDeadline)
		}
		switch endpoint {
		case "/controller/network":
			return []byte(`["0123456789abcdef","aaaaaaaaaaaaaaaa"]`), nil
		case "/controller/network/0123456789abcdef":
			return []byte(`{"name":"unrelated","routes":[]}`), nil
		case "/controller/network/aaaaaaaaaaaaaaaa":
			return []byte(`{"name":"` + common.RANW_NAME + `","id":"attacker-controlled-id","routes":[{"via":""}]}`), nil
		default:
			t.Fatalf("unexpected endpoint %q", endpoint)
			return nil, nil
		}
	}

	if err := getZerotierInfo(ctx, getter, time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || recorder.Code != http.StatusOK {
		t.Fatalf("calls/status = %d, %d; body %q", calls, recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["id"] != "aaaaaaaaaaaaaaaa" || response["name"] != common.RANW_NAME || response["status"] != "online" {
		t.Fatalf("response = %#v", response)
	}
}

func TestGetZeroTierInfoHasOneTotalDeadlineAcrossLaterCalls(t *testing.T) {
	ctx, recorder := newZeroTierInfoTestContext(context.Background())
	calls := 0
	started := time.Now()
	getter := func(ctx context.Context, endpoint string) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			return []byte(`["0123456789abcdef","aaaaaaaaaaaaaaaa"]`), nil
		case 2:
			return []byte(`{"name":"unrelated"}`), nil
		default:
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	if err := getZerotierInfo(ctx, getter, 25*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || recorder.Code != http.StatusInternalServerError || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("calls/status/elapsed = %d, %d, %s", calls, recorder.Code, time.Since(started))
	}
}

func TestGetZeroTierInfoRejectsUnboundedOrUnsafeNetworkLists(t *testing.T) {
	tooMany := make([]string, zeroTierMaximumControllerNets+1)
	for index := range tooMany {
		tooMany[index] = "0123456789abcdef"
	}
	tooManyJSON, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body []byte
	}{
		{name: "malformed", body: []byte(`{"not":"an array"}`)},
		{name: "null", body: []byte(`null`)},
		{name: "too many", body: tooManyJSON},
		{name: "path injection", body: []byte(`["../../../../status"]`)},
		{name: "uppercase noncanonical", body: []byte(`["0123456789ABCDEF"]`)},
		{name: "short", body: []byte(`["1234"]`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, recorder := newZeroTierInfoTestContext(context.Background())
			calls := 0
			getter := func(context.Context, string) ([]byte, error) {
				calls++
				if calls > 1 {
					t.Fatal("unsafe network identifier reached a detail request")
				}
				return test.body, nil
			}
			if err := getZerotierInfo(ctx, getter, time.Second); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), string(test.body)) {
				t.Fatalf("calls/status/body = %d, %d, %q", calls, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestGetZeroTierInfoAdmissionFailureUsesDeclaredGeneric500(t *testing.T) {
	releases := make([]func(), 0)
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for attempts := 0; attempts < 64; attempts++ {
		release, admitted := zerotierapi.TryAcquirePublicRequest()
		if !admitted {
			break
		}
		releases = append(releases, release)
	}
	if len(releases) == 0 || len(releases) == 64 {
		t.Fatalf("could not deterministically saturate ZeroTier admission: %d slots", len(releases))
	}

	ctx, recorder := newZeroTierInfoTestContext(context.Background())
	calls := 0
	if err := getZerotierInfo(ctx, func(context.Context, string) ([]byte, error) {
		calls++
		return nil, nil
	}, time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), zeroTierUnavailableMessage) {
		t.Fatalf("calls/status/body = %d, %d, %q", calls, recorder.Code, recorder.Body.String())
	}
}

func TestGetZeroTierInfoDoesNotDiscloseHelperErrors(t *testing.T) {
	ctx, recorder := newZeroTierInfoTestContext(context.Background())
	secret := "service-token at /var/lib/zerotier-one/authtoken.secret"
	if err := getZerotierInfo(ctx, func(context.Context, string) ([]byte, error) {
		return nil, errors.New(secret)
	}, time.Second); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), secret) || !strings.Contains(recorder.Body.String(), zeroTierUnavailableMessage) {
		t.Fatalf("status/body = %d, %q", recorder.Code, recorder.Body.String())
	}
}

func TestGetZeroTierInfoAlreadyCanceledSkipsStateRequests(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, recorder := newZeroTierInfoTestContext(parent)
	calls := 0
	if err := getZerotierInfo(ctx, func(context.Context, string) ([]byte, error) {
		calls++
		return nil, nil
	}, time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || recorder.Code != http.StatusInternalServerError {
		t.Fatalf("calls/status = %d, %d", calls, recorder.Code)
	}
}

func TestValidZeroTierNetworkIdentifier(t *testing.T) {
	for _, valid := range []string{"0123456789abcdef", "aaaaaaaaaaaaaaaa", "0000000000000000"} {
		if !validZeroTierNetworkIdentifier(valid) {
			t.Fatalf("valid identifier rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDE", "0123456789abcdeg", "../../etc/passwd"} {
		if validZeroTierNetworkIdentifier(invalid) {
			t.Fatalf("invalid identifier accepted: %q", invalid)
		}
	}
}
