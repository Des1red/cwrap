package derive

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"cwrap/internal/recon/report/js"
	"sort"
)

func DeriveNextSteps(ent *knowledge.Entity) []string {
	var out []string
	if ent == nil {
		return out
	}

	// Parameter-driven suggestions (no exclusions)
	pnames := make([]string, 0, len(ent.Params))
	for n := range ent.Params {
		pnames = append(pnames, n)
	}
	sort.Strings(pnames)

	for _, name := range pnames {
		p := ent.Params[name]
		if p == nil {
			continue
		}

		controllable := isRealInputParam(p)

		if p.Enumerable && controllable {
			out = append(out, "Enumerate "+name+" sequentially")
		}
		if (p.PossibleIDOR || p.SuspectIDOR) && controllable {
			out = append(out, "Attempt cross-identity object access via "+name)
		}
		if p.IDLike && p.OwnershipBoundary && controllable {
			out = append(out, "Test horizontal privilege escalation using "+name)
		}
		if p.AuthBoundary && !p.OwnershipBoundary && controllable {
			out = append(out, "Test vertical privilege escalation / role boundary using "+name)
		}
		if p.TokenLike && controllable {
			out = append(out, "Attempt token reuse / swapping / fixation using "+name)
		}
		if p.DebugLike && controllable {
			out = append(out, "Probe debug flags / verbose errors using "+name)
		}
	}

	// Auth-phase suggestions
	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		out = append(out,
			"Test weak credentials and default accounts",
			"Attempt username enumeration",
			"Test auth bypass headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)",
		)
	}

	if ent.SeenSignal(knowledge.SigRoleBoundary) {
		out = append(out,
			"Test vertical privilege escalation — attempt access with lower-privilege token",
			"Probe role confusion via header injection (X-User-Role, X-Forwarded-User)",
			"Check if role is encoded in JWT claims and attempt tampering",
		)
	}

	if ent.SeenSignal(knowledge.SigWeakOpaqueTokenValidation) {
		out = append(out,
			"Test session fixation and session replay",
			"Check whether opaque session IDs are actually validated server-side",
			"Attempt invalid/modified session cookie reuse across protected endpoints",
		)
	}

	// Ownership-phase suggestions
	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		out = append(out, "Attempt cross-user object access (IDOR) across identities")
	}

	// JS leaks suggestions
	if len(ent.Content.JSLeaks) > 0 ||
		len(ent.Content.JSHTTPFlows) > 0 ||
		len(js.ReportableJSFindingKeys(ent)) > 0 {

		out = append(
			out,
			"Review JS leaks, dynamic HTTP flows, role gates, and client-side auth assumptions",
		)
	}

	if ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
		out = append(out,
			"Test whether issued tokens grant authenticated access to protected endpoints",
			"Attempt to reuse credentiallessly issued tokens across sessions",
		)
	}

	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		out = append(out,
			"Attempt signature stripping on JWT (set alg=none)",
			"Test token reuse across sessions and users",
			"Attempt JWT claim tampering (role, user_id elevation)",
		)
	}

	// non-HTTP service
	if ent.State.ProbeCount > 0 &&
		len(ent.HTTP.Methods) == 0 &&
		len(ent.Content.Statuses) == 0 {
		out = append(out, "Probe manually — connect with appropriate client (ftp, ssh, nc)")
		out = append(out, "Check for anonymous access or default credentials")
	}
	out = common.Dedup(out)
	sort.Strings(out)
	return out
}
