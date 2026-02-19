package api

import (
	"bytes"
	"encoding/json"
)

func normalize(body []byte, param string, values []string) []byte {
	out := body

	// replace raw values
	for _, v := range values {
		out = bytes.ReplaceAll(out, []byte(v), []byte("<val>"))
		// replace param=value occurrences (covers url field, logs, etc.)
		out = bytes.ReplaceAll(out, []byte(param+"="+v), []byte(param+"=<val>"))
	}

	return out
}

func normalizeJSON(data []byte) ([]byte, error) {
	var v any

	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	clean := stripValues(v)

	return json.Marshal(clean)
}

func stripValues(v any) any {
	switch val := v.(type) {

	case map[string]any:
		out := map[string]any{}
		for k, sub := range val {
			out[k] = stripValues(sub)
		}
		return out

	case []any:
		arr := make([]any, len(val))
		for i, sub := range val {
			arr[i] = stripValues(sub)
		}
		return arr

	default:
		// replace ALL leaf values
		return "<val>"
	}
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
