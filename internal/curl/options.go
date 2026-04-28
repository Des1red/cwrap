package curl

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

	if !req.Flags.NoFollow {
		args = append(args, "-L")
	}

	/* auto cookie jar */
	if req.Flags.AutoCookie && len(req.Flags.Cookies) > 0 {
		fmt.Println("cwrap: ignoring manual cookies because auto-cookie is enabled")
	}
	if req.Flags.AutoCookie {

		jar := jarPath()

		args = append(args,
			"-b", jar, // read cookies
			"-c", jar, // write cookies
		)

	} else if len(req.Flags.Cookies) > 0 {

		/* manual cookies */

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
