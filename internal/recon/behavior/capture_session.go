package behavior

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/session"
	"net/http"
)

func captureSession(ent *knowledge.Entity, resp *http.Response, rawURL string) {

	updated := false

	for _, c := range resp.Cookies() {

		if ent.SessionCookies[c.Name] != c.Value {
			ent.SessionCookies[c.Name] = c.Value
			ent.SessionIssued = true
			updated = true
		}
	}

	if updated {
		var out session.Store
		for name, value := range ent.SessionCookies {
			out.Cookies = append(out.Cookies, session.Cookie{
				Name:  name,
				Value: value,
			})
		}
		session.Save(rawURL, &out)
	}
}
