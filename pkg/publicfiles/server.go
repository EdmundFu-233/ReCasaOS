package publicfiles

import (
	"errors"
	"math"
	"math/bits"
	"net/http"
	"time"
)

const (
	DefaultReadHeaderTimeout          = 5 * time.Second
	DefaultReadTimeout                = 15 * time.Second
	DefaultDownloadWriteIdleTimeout   = 30 * time.Second
	DefaultDownloadMinimumRateGrace   = 30 * time.Second
	DefaultDownloadMinimumBytesPerSec = int64(64 << 10)
	DefaultConnectionIdleTimeout      = 30 * time.Second
	DefaultMaxHeaderBytes             = 32 << 10
	maxDownloadDeadlineCreditBytes    = 64 << 10
)

var (
	errDownloadDeadlineUnavailable = errors.New("public file download deadline control is unavailable")
	errDownloadWriteIdleExceeded   = errors.New("public file download write idle deadline exceeded")
)

type httpServerConfig struct {
	readHeaderTimeout        time.Duration
	readTimeout              time.Duration
	baseWriteTimeout         time.Duration
	connectionIdleTimeout    time.Duration
	maxHeaderBytes           int
	downloadWriteIdleTimeout time.Duration
	downloadMinimumRateGrace time.Duration
	downloadMinimumRate      int64
	now                      func() time.Time
}

func defaultHTTPServerConfig() httpServerConfig {
	return httpServerConfig{
		readHeaderTimeout:        DefaultReadHeaderTimeout,
		readTimeout:              DefaultReadTimeout,
		baseWriteTimeout:         DefaultDownloadWriteIdleTimeout,
		connectionIdleTimeout:    DefaultConnectionIdleTimeout,
		maxHeaderBytes:           DefaultMaxHeaderBytes,
		downloadWriteIdleTimeout: DefaultDownloadWriteIdleTimeout,
		downloadMinimumRateGrace: DefaultDownloadMinimumRateGrace,
		downloadMinimumRate:      DefaultDownloadMinimumBytesPerSec,
		now:                      time.Now,
	}
}

// NewHTTPServer returns the dedicated public-file server with finite header,
// body and connection limits. File responses replace the server's absolute
// write cutoff with a progress-aware idle deadline and cumulative minimum-rate
// budget. Production callers must supply the reviewed systemd-activated
// loopback listener; this package never binds a network address itself.
func NewHTTPServer(handler http.Handler) *http.Server {
	return newHTTPServer(handler, defaultHTTPServerConfig())
}

func newHTTPServer(handler http.Handler, config httpServerConfig) *http.Server {
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	if config.readHeaderTimeout <= 0 || config.readTimeout <= 0 || config.baseWriteTimeout <= 0 ||
		config.connectionIdleTimeout <= 0 || config.maxHeaderBytes <= 0 ||
		config.downloadWriteIdleTimeout <= 0 || config.downloadMinimumRateGrace <= 0 ||
		config.downloadMinimumRate <= 0 || config.now == nil {
		panic("invalid public file HTTP server configuration")
	}

	return &http.Server{
		Handler:           progressBoundedDownloadHandler(handler, config),
		ReadHeaderTimeout: config.readHeaderTimeout,
		ReadTimeout:       config.readTimeout,
		WriteTimeout:      config.baseWriteTimeout,
		IdleTimeout:       config.connectionIdleTimeout,
		MaxHeaderBytes:    config.maxHeaderBytes,
	}
}

func progressBoundedDownloadHandler(next http.Handler, config httpServerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != BasePath+"/api/file" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		writer := &progressBoundedWriter{
			ResponseWriter: w,
			started:        config.now(),
			now:            config.now,
			idleTimeout:    config.downloadWriteIdleTimeout,
			minimumGrace:   config.downloadMinimumRateGrace,
			minimumRate:    config.downloadMinimumRate,
		}
		writer.lastProgress = writer.started
		next.ServeHTTP(writer, r)
	})
}

// progressBoundedWriter deliberately does not implement io.ReaderFrom. This
// keeps http.ServeContent copies on bounded Write calls so every chunk gets a
// fresh idle deadline and is charged to the cumulative rate budget.
type progressBoundedWriter struct {
	http.ResponseWriter
	started      time.Time
	now          func() time.Time
	idleTimeout  time.Duration
	minimumGrace time.Duration
	minimumRate  int64
	bodyBytes    int64
	lastProgress time.Time
	wroteHeader  bool
	writeErr     error
}

func (w *progressBoundedWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *progressBoundedWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if err := w.setDeadline(0); err != nil {
		w.writeErr = err
		clearDownloadRepresentationHeaders(w.Header())
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Connection", "close")
		w.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func clearDownloadRepresentationHeaders(header http.Header) {
	for _, name := range []string{
		"Accept-Ranges",
		"Content-Disposition",
		"Content-Encoding",
		"Content-Location",
		"Content-Length",
		"Content-Range",
		"Content-Type",
		"ETag",
		"Last-Modified",
		"Trailer",
		"Transfer-Encoding",
	} {
		header.Del(name)
	}
}

func (w *progressBoundedWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if err := w.setDeadline(len(payload)); err != nil {
		w.writeErr = err
		return 0, err
	}
	written, err := w.ResponseWriter.Write(payload)
	if written > 0 {
		w.lastProgress = w.now()
		if int64(written) > math.MaxInt64-w.bodyBytes {
			w.bodyBytes = math.MaxInt64
		} else {
			w.bodyBytes += int64(written)
		}
	}
	if err != nil {
		w.writeErr = err
	}
	return written, err
}

func (w *progressBoundedWriter) setDeadline(nextBytes int) error {
	now := w.now()
	if w.lastProgress.IsZero() {
		w.lastProgress = w.started
	}
	if !now.Before(w.lastProgress.Add(w.idleTimeout)) {
		return errDownloadWriteIdleExceeded
	}
	deadline := now.Add(w.idleTimeout)
	accounted := w.bodyBytes
	if nextBytes > 0 {
		if nextBytes > maxDownloadDeadlineCreditBytes {
			nextBytes = maxDownloadDeadlineCreditBytes
		}
		if int64(nextBytes) > math.MaxInt64-accounted {
			accounted = math.MaxInt64
		} else {
			accounted += int64(nextBytes)
		}
	}
	rateDeadline := w.started.Add(w.minimumGrace).Add(rateAllowance(accounted, w.minimumRate))
	if rateDeadline.Before(deadline) {
		deadline = rateDeadline
	}
	if err := http.NewResponseController(w.ResponseWriter).SetWriteDeadline(deadline); err != nil {
		return errors.Join(errDownloadDeadlineUnavailable, err)
	}
	return nil
}

func rateAllowance(byteCount, bytesPerSecond int64) time.Duration {
	if byteCount <= 0 || bytesPerSecond <= 0 {
		return 0
	}
	high, low := bits.Mul64(uint64(byteCount), uint64(time.Second))
	divisor := uint64(bytesPerSecond)
	if high >= divisor {
		return time.Duration(math.MaxInt64)
	}
	quotient, remainder := bits.Div64(high, low, divisor)
	if remainder != 0 {
		if quotient == math.MaxInt64 {
			return time.Duration(math.MaxInt64)
		}
		quotient++
	}
	if quotient > math.MaxInt64 {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(quotient)
}
