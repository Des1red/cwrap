package api

import (
	"cwrap/internal/recon/knowledge"
	"encoding/json"
)

func (e *Engine) extractJSON(ent *knowledge.Entity, data []byte) {

	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return
	}

	walkJSON(e, ent, v)
}

var reflectionKeys = map[string]bool{
	"headers": true,
	"origin":  true,
	"url":     true,
	"args":    true,
	"files":   true,
	"form":    true,
	"json":    true,
	"data":    true,
}

func walkJSON(e *Engine, ent *knowledge.Entity, v any) {

	switch val := v.(type) {

	case map[string]any:
		for k, sub := range val {

			// skip transport reflection objects
			if reflectionKeys[k] {
				continue
			}

			ent.AddParam(k, knowledge.ParamJSON)
			e.k.AddParam(k)
			walkJSON(e, ent, sub)
		}

	case []any:
		for _, item := range val {
			walkJSON(e, ent, item)
		}
	}
}

// fallback for non-JSON responses: strip numbers to get a rough structural diff
func stripNumbers(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	for i := range out {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = '#'
		}
	}
	return out
}
