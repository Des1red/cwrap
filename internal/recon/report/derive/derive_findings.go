package derive

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"fmt"
	"sort"
)

func DeriveFindings(ent *knowledge.Entity) []string {
	var out []string
	if ent == nil {
		return out
	}

	// Signals-based findings
	if ent.SeenSignal(knowledge.SigAdminSurface) {
		out = append(out, "Administrative surface detected")
	}

	if ent.SeenSignal(knowledge.SigFileUpload) {
		out = append(out, "File upload surface detected")
	}

	if ent.SeenSignal(knowledge.SigSensitiveKeyword) {
		out = append(out, "Sensitive keywords detected in content/JS")
	}

	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		out = append(out, "Authentication/authorization boundary observed")
	}
	if ent.SeenSignal(knowledge.SigRoleBoundary) {
		out = append(out, "Role/permission boundary observed — authenticated identity denied access")
	}

	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		out = append(out, "Object ownership enforcement observed")
	}
	if ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
		out = append(out, "Server issues tokens/sessions without credentials — credentialless authentication bypass possible")
	}

	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		out = append(out, "Broken token validation — server accepted a tampered/invalid token")
	}

	if ent.SeenSignal(knowledge.SigWeakOpaqueTokenValidation) {
		out = append(out, "Weak opaque token/session validation — server accepted a corrupted session/token cookie")
	}

	if ent.HTTP.CORSPermissive {
		out = append(out, fmt.Sprintf("Permissive CORS configuration — credentialed cross-origin requests allowed (origin: %s)", ent.HTTP.CORSOrigin))
	}

	if ent.SeenSignal(knowledge.SigMissingSecurityHeaders) {
		out = append(out, fmt.Sprintf("Missing security headers: %s", common.JoinComma(ent.HTTP.MissingSecurityHeaders)))
	}

	if ent.SeenSignal(knowledge.SigPermissiveFrameAncestors) {
		out = append(out, fmt.Sprintf("Permissive frame-ancestors policy weakens clickjacking protection (value: %s)", ent.HTTP.FrameAncestors))
	}
	// Param-based findings
	pnames := make([]string, 0, len(ent.Params))
	for n := range ent.Params {
		pnames = append(pnames, n)
	}
	sort.Strings(pnames)

	for _, name := range idorFindingParams(ent) {
		out = append(out, fmt.Sprintf("Horizontal privilege escalation possible via param: %s", name))
	}

	for _, name := range suspectIDORFindingParams(ent) {
		out = append(out, fmt.Sprintf("Suspect IDOR surface via param: %s", name))
	}

	for _, name := range pnames {
		p := ent.Params[name]
		if p == nil {
			continue
		}

		if p.Enumerable && p.LikelyObjectAccess && isRealInputParam(p) {
			out = append(out, fmt.Sprintf("Object enumeration possible via param: %s", name))
		}
		if p.DebugLike {
			out = append(out, fmt.Sprintf("Debug functionality exposed via param: %s", name))
		}
		if p.TokenLike {
			out = append(out, fmt.Sprintf("Token-like parameter observed: %s", name))
		}

		if p.IdentityAccess != nil && p.IdentityAccess["anonymous"] > 0 && len(p.IdentityDenied) > 0 {
			out = append(out, fmt.Sprintf("Unauthenticated access observed (identity: anonymous) via param behavior: %s", name))
		}
	}

	// JS leaks are always findings in full report
	if len(ent.Content.JSLeaks) > 0 {
		out = append(out, fmt.Sprintf("JS leaks present: %d", len(ent.Content.JSLeaks)))
	}

	// non-HTTP service
	if ent.State.ProbeCount > 0 &&
		len(ent.HTTP.Methods) == 0 &&
		len(ent.Content.Statuses) == 0 {
		out = append(out, "Endpoint unreachable over HTTP — may be a non-HTTP service (FTP, SSH, etc.)")
	}

	out = common.Dedup(out)
	sort.Strings(out)
	return out
}
