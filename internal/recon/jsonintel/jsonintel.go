package jsonintel

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/paramintel"
	"encoding/json"
)

// reflectionKeys are transport-layer echo keys that appear in debugging
// proxies and test servers (httpbin-style). They reflect request metadata
// rather than real application schema, so we skip them.
var reflectionKeys = map[string]bool{
	// transport-layer echo keys (httpbin-style)
	"headers": true,
	"origin":  true,
	"url":     true,
	"args":    true,
	"files":   true,
	"form":    true,
	"json":    true,
	"data":    true,
	// error envelope keys — present on failure responses,
	// not part of the success schema
	"error":   true,
	"message": true,
	"detail":  true,
	"details": true,
	"code":    true,
	"status":  true,
	"trace":   true,
	"errors":  true,
}

// ExtractParams walks a JSON response body and registers discovered keys
// as ParamJSON parameters on the entity. Only walks 2 levels deep —
// top-level keys and one level down. Deeper nesting is almost always
// data content, not query/body parameters.
//
// Both the HTTP and API engines call this whenever a response is JSON.
func ExtractParams(ent *knowledge.Entity, k *knowledge.Knowledge, data []byte) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return
	}
	walkJSON(ent, k, v, 0)
}

func walkJSON(ent *knowledge.Entity, k *knowledge.Knowledge, v any, depth int) {
	// depth > 2 means we're inside nested data objects — not param candidates
	if depth > 2 {
		return
	}
	switch val := v.(type) {
	case map[string]any:
		for key, sub := range val {
			if reflectionKeys[key] {
				continue
			}
			ent.AddParam(key, knowledge.ParamJSON)
			k.AddParam(key)
			p := ent.Params[key]
			if p != nil {
				paramintel.ClassifyParam(ent, p)
			}
			walkJSON(ent, k, sub, depth+1)
		}
	case []any:
		// walk only the first element of arrays —
		// all items share the same schema, no need to walk every one
		if len(val) > 0 {
			walkJSON(ent, k, val[0], depth+1)
		}
	}
}
