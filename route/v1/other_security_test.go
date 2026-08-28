package v1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestGetSearchResultRejectsOversizedRequestBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/other/search", strings.NewReader(`{"url":"`+strings.Repeat("a", int(maxSearchRequestBodySize))+`"}`))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := GetSearchResult(echo.New().NewContext(request, response)); err != nil {
		t.Fatalf("GetSearchResult returned error: %v", err)
	}
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
	if strings.Contains(response.Body.String(), strings.Repeat("a", 128)) {
		t.Fatal("oversized request data was reflected in the response")
	}
}

func TestSearchRequestPreservesLegacyQueryBinding(t *testing.T) {
	searchURL := "https://www.google.com/complete/search?q=recasaos"
	request := httptest.NewRequest(http.MethodGet, "/v1/other/search?url="+url.QueryEscape(searchURL), nil)
	response := httptest.NewRecorder()

	values, err := bindSearchRequest(echo.New().NewContext(request, response))
	if err != nil {
		t.Fatalf("bindSearchRequest returned error: %v", err)
	}
	if values["url"] != searchURL {
		t.Fatalf("bound url = %q, want %q", values["url"], searchURL)
	}
}

func TestGetSearchResultRejectsMalformedRequestBeforeServiceAccess(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/other/search", strings.NewReader(`{"url":`))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := GetSearchResult(echo.New().NewContext(request, response)); err != nil {
		t.Fatalf("GetSearchResult returned error: %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}
