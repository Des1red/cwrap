package curl

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/session"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func jarPath() string {
	base := model.ConfigDir()
	return filepath.Join(base, "cookies.txt")
}

func SyncJarToSession(targetURL string) error {
	jar := jarPath()
	b, err := os.ReadFile(jar)
	if err != nil {
		return nil // no jar yet, nothing to sync
	}

	store, _ := session.Load(targetURL)
	ident := store.Identities["session"]
	if ident == nil {
		ident = &session.IdentitySession{
			Cookies: make(map[string]*session.CookieEntry),
		}
		store.Identities["session"] = ident
	}

	// Netscape cookie jar format: tab-separated, skip comment lines
	for _, line := range strings.Split(string(b), "\n") {
		// handle HttpOnly cookies — Netscape format prefixes domain with #HttpOnly_
		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			line = line[len("#HttpOnly_"):]
			httpOnly = true
		} else if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		name := fields[5]
		value := fields[6]
		ident.Cookies[name] = &session.CookieEntry{
			Name:     name,
			Value:    value,
			Source:   "server",
			Path:     fields[2],
			Secure:   fields[3] == "TRUE",
			HttpOnly: httpOnly,
		}
	}

	ident.Updated = time.Now()
	return session.Save(targetURL, store)
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
