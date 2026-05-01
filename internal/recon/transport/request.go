package transport

import (
	"cwrap/internal/httpcore"
	"cwrap/internal/model"
	"io"
	"net/http"
	"strings"
)

func Build(req model.Request) (*http.Request, error) {

	finalURL, err := applyQuery(req.URL, req.Flags.Query)
	if err != nil {
		return nil, err
	}

	headers := httpcore.BuildHeaders(req)

	var bodyReader io.Reader
	if req.Flags.Body != "" {
		bodyReader = strings.NewReader(req.Flags.Body)
	}

	r, err := http.NewRequest(req.Method, finalURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for _, h := range headers {
		r.Header.Set(h.Name, h.Value)
	}

	return r, nil
}
