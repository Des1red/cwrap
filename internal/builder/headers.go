package builder

import (
	"cwrap/internal/model"
)

func appendHeaderArgs(args []string, headers []model.Header) []string {
	for _, h := range headers {
		args = append(args, "-H", h.Name+": "+h.Value)
	}
	return args
}
