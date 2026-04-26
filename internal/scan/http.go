package scan

import (
	"crypto/tls"
	"cwrap/internal/httpcore"
	"cwrap/internal/model"
	"fmt"
	"net/http"
	"sync"
	"time"
)

func newPlainClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        workers,
			MaxIdleConnsPerHost: workers,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newClient(req model.Request) *http.Client {
	base := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        workers,
		MaxIdleConnsPerHost: workers,
	}

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &authTransport{
			base: base,
			req:  req,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// authTransport applies the full cwrap header stack (profile, bearer, custom headers)
// plus cookies to every scan probe — same path as the rest of the tool.
type authTransport struct {
	base      http.RoundTripper
	req       model.Request
	debugOnce sync.Once
}

func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())

	for _, h := range httpcore.BuildHeaders(t.req) {
		if r.Header.Get(h.Name) == "" {
			r.Header.Set(h.Name, h.Value)
		}
	}

	r.Header.Del("Accept-Encoding")

	for _, c := range t.req.Flags.Cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}

	if t.req.Flags.Debug {
		t.debugOnce.Do(func() {
			fmt.Printf("  probe headers:\n")
			for k, v := range r.Header {
				fmt.Printf("     %s: %s\n", k, v)
			}
			fmt.Println()
		})
	}

	return t.base.RoundTrip(r)
}
