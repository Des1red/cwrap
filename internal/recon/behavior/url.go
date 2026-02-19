package behavior

import "net/url"

func extractCurrentValue(raw, key string) string {

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	return u.Query().Get(key)
}
