package api

import (
	"encoding/json"
	"net/url"
	"strings"
)

func (e *Engine) normalizeLink(baseURL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	if strings.HasPrefix(raw, "#") {
		return "", false
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") {
		return "", false
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}

	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	abs := base.ResolveReference(ref)
	abs.Fragment = ""

	if abs.Host != base.Host {
		return "", false
	}

	return abs.String(), true
}

func normalizeJSONWithParam(data []byte, param string) ([]byte, error) {

	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	clean := stripParamValue(v, param)

	return json.Marshal(clean)
}

func stripParamValue(v any, param string) any {

	switch val := v.(type) {

	case map[string]any:
		out := map[string]any{}
		for k, sub := range val {

			// only erase the parameter value
			if k == param {
				out[k] = "<param>"
			} else {
				out[k] = stripParamValue(sub, param)
			}
		}
		return out

	case []any:
		arr := make([]any, len(val))
		for i, sub := range val {
			arr[i] = stripParamValue(sub, param)
		}
		return arr

	default:
		return val
	}
}
