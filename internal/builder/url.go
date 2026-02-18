package builder

import (
	"cwrap/internal/model"
	"net/url"
)

func applyQuery(raw string, q []model.QueryParam) string {
	if len(q) == 0 {
		return raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	values := u.Query()

	for _, p := range q {
		values.Add(p.Key, p.Value)
	}

	u.RawQuery = values.Encode()
	return u.String()
}
