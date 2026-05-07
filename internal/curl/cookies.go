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

	store, err := session.Load(targetURL)
	if err != nil {
		return err
	}

	ident := store.Identities["session"]
	if ident == nil {
		ident = &session.IdentitySession{
			Cookies: make(map[string]*session.CookieEntry),
		}
		store.Identities["session"] = ident
	}

	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			line = strings.TrimPrefix(line, "#HttpOnly_")
			httpOnly = true
		} else if strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}

		name := fields[5]
		value := fields[6]
		if name == "" {
			continue
		}

		ident.Cookies[name] = &session.CookieEntry{
			Name:     name,
			Value:    value,
			Source:   "server",
			Domain:   fields[0],
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
		if strings.HasPrefix(l, "#HttpOnly_") {
			l = strings.TrimPrefix(l, "#HttpOnly_")
		} else if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}

		fields := strings.Fields(l)
		if len(fields) < 7 {
			continue
		}

		domain := fields[0]
		name := fields[5]
		value := fields[6]

		if !strings.Contains(host, domain) && !strings.Contains(domain, host) {
			continue
		}

		ln := strings.ToLower(name)
		if strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf") {
			return name, value
		}

	}

	return "", ""
}
