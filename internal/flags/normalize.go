package flags

import (
	"cwrap/internal/model"
	"strings"
)

func normalizeBasic(f *model.Flags, r rawInput) {

	f.Proxy = strings.TrimSpace(f.Proxy)
	f.Profile = strings.ToLower(strings.TrimSpace(f.Profile))

	for _, h := range r.headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		f.Headers = append(f.Headers, model.Header{
			Name:  strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}

	for _, c := range r.cookies {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			continue
		}
		f.Cookies = append(f.Cookies, model.Cookie{
			Name:  strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}
}
