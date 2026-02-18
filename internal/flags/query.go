package flags

import (
	"cwrap/internal/model"
	"strings"
)

func normalizeQuery(f *model.Flags, r rawInput) {
	for _, q := range r.query {
		parts := strings.SplitN(q, "=", 2)
		if len(parts) != 2 {
			continue
		}
		f.Query = append(f.Query, model.QueryParam{
			Key:   strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}
}
