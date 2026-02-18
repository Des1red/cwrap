package intent

import (
	"strconv"
	"strings"
)

func inferJSONValue(v string) any {

	l := strings.ToLower(v)

	// null
	if l == "null" {
		return nil
	}

	// bool
	if l == "true" {
		return true
	}
	if l == "false" {
		return false
	}

	// int
	if i, err := strconv.Atoi(v); err == nil {
		return i
	}

	// float
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f
	}

	// string fallback
	return v
}

func insertJSONPath(root map[string]any, key string, value any) {

	parts := strings.Split(key, ".")
	last := len(parts) - 1

	cur := root

	for i, p := range parts {

		// last segment → write value
		if i == last {

			if existing, ok := cur[p]; ok {

				switch e := existing.(type) {

				case []any:
					cur[p] = append(e, value)

				default:
					cur[p] = []any{e, value}
				}

			} else {
				cur[p] = value
			}

			return
		}

		// intermediate object
		next, ok := cur[p]
		if !ok {
			n := map[string]any{}
			cur[p] = n
			cur = n
			continue
		}

		// ensure object
		if obj, ok := next.(map[string]any); ok {
			cur = obj
		} else {
			// conflicting type → overwrite into object
			n := map[string]any{}
			cur[p] = n
			cur = n
		}
	}
}
