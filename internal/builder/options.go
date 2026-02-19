package builder

import (
	"cwrap/internal/httpcore"
	"cwrap/internal/model"
	"fmt"
	"strings"
)

func buildOptions(args []string, req model.Request) []string {

	if httpcore.SupportsCompression(req.Flags.Profile) {
		args = append(args, "--compressed")
	}

	if req.Flags.Follow {
		args = append(args, "-L")
	}

	if len(req.Flags.Cookies) > 0 {
		var parts []string
		for _, c := range req.Flags.Cookies {
			parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		args = append(args, "-b", strings.Join(parts, "; "))
	}

	if req.Flags.Proxy != "" {
		args = append(args, "-x", req.Flags.Proxy)
	}

	return args
}
