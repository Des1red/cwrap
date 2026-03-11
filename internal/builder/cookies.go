package builder

import (
	"os"
	"path/filepath"
	"strings"
)

func jarPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cwrap_cookies.txt")
}

func readCSRFCookie(host string) (string, string) {

	data, err := os.ReadFile(jarPath())
	if err != nil {
		return "", ""
	}

	lines := strings.Split(string(data), "\n")

	for _, l := range lines {

		if strings.HasPrefix(l, "#") {
			continue
		}

		fields := strings.Fields(l)

		if len(fields) < 7 {
			continue
		}

		domain := fields[0]
		name := fields[5]
		value := fields[6]

		/* match domain */

		if !strings.Contains(host, domain) && !strings.Contains(domain, host) {
			continue
		}

		switch strings.ToLower(name) {
		case "csrf_token", "csrftoken", "xsrf-token", "xsrf", "_csrf":
			return name, value
		}
	}

	return "", ""
}
