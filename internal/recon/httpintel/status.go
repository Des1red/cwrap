package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
)

// learnStatus tracks status code counts and status-based auth boundary signals.
func learnStatus(ent *knowledge.Entity, resp *http.Response) {
	ent.Content.Statuses[resp.StatusCode]++

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		ent.HTTP.AuthLikely = true
	}
}
