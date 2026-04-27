package behavior

import "cwrap/internal/recon/knowledge"

// stripSPAShellSignals removes auth signals from HTML entities that also have
// PublicAccess — these are SPA catchall routes, not real auth boundaries.
// The server returns 200+HTML for every unknown route regardless of auth,
// so any 403s observed are incidental (wrong method, missing body, CSRF).
// JSON endpoints are the ground truth for auth boundary analysis.
func (e *Engine) stripSPAShellSignals() {
	for _, ent := range e.k.Entities {
		if ent.Content.LooksLikeHTML && ent.SeenSignal(knowledge.SigPublicAccess) {
			delete(ent.Signals.Tags, knowledge.SigAuthBoundary)
			delete(ent.Signals.Tags, knowledge.SigRoleBoundary)
			delete(ent.Signals.Tags, knowledge.SigCredentiallessTokenIssuance)
			delete(ent.Signals.Tags, knowledge.SigObjectOwnership)
			delete(ent.Signals.Tags, knowledge.SigPossibleIDOR)
			ent.HTTP.AuthLikely = false
		}

		if isStaticAsset(ent) {
			delete(ent.Signals.Tags, knowledge.SigPublicAccess)
		}
	}
}
