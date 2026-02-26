package transport

import (
	"cwrap/internal/model"
	"net/http"
	"time"
)

func Do(req model.Request) (*http.Response, error) {

	r, err := Build(req)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(r)
}
