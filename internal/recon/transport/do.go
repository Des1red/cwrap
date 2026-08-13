package transport

import (
	"crypto/tls"
	"cwrap/internal/model"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	retryTimeout   = 30 * time.Second
)

func Do(req model.Request) (*http.Response, error) {
	resp, err := doOnce(req, defaultTimeout)
	if err == nil {
		return resp, nil
	}

	if !isTimeoutError(err) || !isSafeMethod(req.Method) {
		return nil, err
	}

	if req.Flags.Debug {
		fmt.Printf("[RETRY] %s %s timed out after %s, retrying with %s timeout: %v\n",
			req.Method, req.URL, defaultTimeout, retryTimeout, err)
	}

	return doOnce(req, retryTimeout)
}

func doOnce(req model.Request, timeout time.Duration) (*http.Response, error) {
	r, err := Build(req)
	if err != nil {
		return nil, err
	}
	dumpRequest(r, req.Flags.Debug)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client.Do(r)
}

// isTimeoutError reports whether err represents a client-side timeout
// (Client.Timeout exceeded) rather than some other failure (connection
// refused, TLS error, DNS failure, etc.) — only timeouts get retried.
func isTimeoutError(err error) bool {
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// isSafeMethod reports whether a method is safe to retry blindly. GET,
// HEAD, and OPTIONS never change server state, so a retry after a timeout
// can't double-submit a mutation — POST/PUT/PATCH/DELETE are excluded
// because the original request may have completed server-side even
// though the client never saw the response.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
