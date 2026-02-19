package transport

import (
	"cwrap/internal/model"
	"net/url"
)

func applyQuery(raw string, q []model.QueryParam) (string, error) {
	if len(q) == 0 {
		return raw, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	qs := u.Query()
	for _, p := range q {
		if p.Key == "" {
			continue
		}
		qs.Set(p.Key, p.Value)
	}
	u.RawQuery = qs.Encode()
	return u.String(), nil
}
