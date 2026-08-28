package httper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/tidwall/gjson"
)

const (
	legacyGetMaximumResponseBytes         int64 = 4 << 20
	legacyPersonGetMaximumResponseBytes   int64 = 256 << 10
	legacyPostMaximumResponseBytes        int64 = 1 << 20
	legacyZeroTierMaximumResponseBytes    int64 = 16 << 20
	legacyOasisTokenMaximumResponseBytes  int64 = 64 << 10
	legacyOasisTargetMaximumResponseBytes int64 = 1 << 20
)

var (
	errLegacyInvalidResponse  = errors.New("invalid legacy HTTP response")
	errLegacyResponseTooLarge = errors.New("legacy HTTP response is too large")
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type boundedResponse struct {
	body       []byte
	statusCode int
}

type legacyTransportError struct {
	err error
}

func (e *legacyTransportError) Error() string {
	return e.err.Error()
}

func (e *legacyTransportError) Unwrap() error {
	return e.err
}

func doBounded(
	ctx context.Context,
	client httpDoer,
	method string,
	target string,
	requestBody io.Reader,
	headers http.Header,
	maximumResponseBytes int64,
) (boundedResponse, error) {
	if ctx == nil || client == nil || maximumResponseBytes < 0 || maximumResponseBytes == math.MaxInt64 {
		return boundedResponse{}, errLegacyInvalidResponse
	}
	if err := ctx.Err(); err != nil {
		return boundedResponse{}, err
	}

	request, err := http.NewRequestWithContext(ctx, method, target, requestBody)
	if err != nil {
		return boundedResponse{}, err
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}

	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return boundedResponse{}, &legacyTransportError{err: err}
	}
	if response == nil {
		return boundedResponse{}, errLegacyInvalidResponse
	}
	if response.Body == nil {
		return boundedResponse{statusCode: response.StatusCode}, errLegacyInvalidResponse
	}
	defer response.Body.Close()

	result, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return boundedResponse{statusCode: response.StatusCode}, fmt.Errorf("read legacy HTTP response: %w", err)
	}
	if int64(len(result)) > maximumResponseBytes {
		return boundedResponse{statusCode: response.StatusCode}, errLegacyResponseTooLarge
	}

	return boundedResponse{body: result, statusCode: response.StatusCode}, nil
}

func legacyHeaders(head map[string]string) http.Header {
	headers := make(http.Header, len(head))
	for name, value := range head {
		headers.Add(name, value)
	}
	return headers
}

func printLegacyTransportError(err error) {
	var transportError *legacyTransportError
	if errors.As(err, &transportError) {
		fmt.Println(transportError.err)
	}
}

func getBounded(ctx context.Context, target string, head map[string]string, maximumResponseBytes int64) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := doBounded(
		ctx,
		client,
		http.MethodGet,
		target,
		nil,
		legacyHeaders(head),
		maximumResponseBytes,
	)
	if err != nil {
		printLegacyTransportError(err)
		return "", err
	}
	return string(response.body), nil
}

// 发送GET请求
// url:请求地址
// response:请求返回的内容
func Get(url string, head map[string]string) (response string) {
	response, _ = getBounded(context.Background(), url, head, legacyGetMaximumResponseBytes)
	return
}

// 发送GET请求
// url:请求地址
// response:请求返回的内容
func PersonGet(url string) (response string) {
	client := &http.Client{Timeout: 5 * time.Second}
	result, err := doBounded(
		context.Background(),
		client,
		http.MethodGet,
		url,
		nil,
		nil,
		legacyPersonGetMaximumResponseBytes,
	)
	if err != nil {
		return ""
	}
	response = string(result.body)
	return
}

// 发送POST请求
// url:请求地址，data:POST请求提交的数据,contentType:请求体格式，如：application/json
// content:请求放回的内容
func Post(url string, data []byte, contentType string, head map[string]string) (content string) {
	client := &http.Client{Timeout: 5 * time.Second}
	headers := make(http.Header, len(head)+1)
	headers.Add("content-type", contentType)
	for name, value := range head {
		headers.Add(name, value)
	}
	response, err := doBounded(
		context.Background(),
		client,
		http.MethodPost,
		url,
		bytes.NewBuffer(data),
		headers,
		legacyPostMaximumResponseBytes,
	)
	if err != nil {
		printLegacyTransportError(err)
		return ""
	}
	content = string(response.body)
	return
}

// 发送POST请求
// url:请求地址，data:POST请求提交的数据,contentType:请求体格式，如：application/json
// content:请求放回的内容
func ZeroTierGet(url string, head map[string]string) (content string, code int) {
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := doBounded(
		context.Background(),
		client,
		http.MethodGet,
		url,
		nil,
		legacyHeaders(head),
		legacyZeroTierMaximumResponseBytes,
	)
	if err != nil {
		return "", response.statusCode
	}
	code = response.statusCode
	content = string(response.body)
	return
}

// 发送GET请求
// url:请求地址
// response:请求返回的内容
func OasisGet(url string) (response string) {
	ctx := context.Background()
	tokenResponse, err := getBounded(
		ctx,
		config.ServerInfo.ServerApi+"/token",
		nil,
		legacyOasisTokenMaximumResponseBytes,
	)
	if err != nil {
		return ""
	}

	head := map[string]string{"Authorization": gjson.Get(tokenResponse, "data").String()}
	response, _ = getBounded(ctx, url, head, legacyOasisTargetMaximumResponseBytes)
	return
}
