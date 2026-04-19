package api

import (
	"encoding/json"
)

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
