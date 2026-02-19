package transport

import (
	"cwrap/internal/httpcore"
	"cwrap/internal/model"
	"net/http"
)

func Build(req model.Request) (*http.Request, error) {

	finalURL, err := applyQuery(req.URL, req.Flags.Query)
	if err != nil {
		return nil, err
	}

	headers := httpcore.BuildHeaders(req)

	r, err := http.NewRequest(req.Method, finalURL, nil)
	if err != nil {
		return nil, err
	}

	for _, h := range headers {
		r.Header.Set(h.Name, h.Value)
	}

	return r, nil
}
