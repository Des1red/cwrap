package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"io"
	"sort"
)

// ---- derivation helpers ----

func sortedEntityURLs(k *knowledge.Knowledge) []string {
	urls := make([]string, 0, len(k.Entities))
	for u := range k.Entities {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, on := range m {
		if on {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func activeSignals(ent *knowledge.Entity) []string {
	if ent == nil || len(ent.Signals.Tags) == 0 {
		return nil
	}
	var out []string
	for s, on := range ent.Signals.Tags {
		if on {
			out = append(out, s.String())
		}
	}
	sort.Strings(out)
	return out
}

func identityKindLabel(k knowledge.IdentityKind) string {
	switch k {
	case knowledge.IdentityUnknown:
		return "IdentityUnknown"
	case knowledge.IdentityNone:
		return "IdentityNone"
	case knowledge.IdentityBootstrap:
		return "IdentityBootstrap"
	case knowledge.IdentityUser:
		return "IdentityUser"
	case knowledge.IdentityElevated:
		return "IdentityElevated"
	case knowledge.IdentityInvalid:
		return "IdentityInvalid"
	default:
		return "IdentityKind(?)"
	}
}

func emptyAsNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func writeStringIntMap(w io.Writer, prefix string, m map[string]int) {
	if len(m) == 0 {
		fmt.Fprintln(w, prefix+"(none)")
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s: %d\n", prefix, k, m[k])
	}
}

func deriveFindings(ent *knowledge.Entity) []string {
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
	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		out = append(out, "Object ownership enforcement observed")
	}

	// Param-based findings
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

		if p.PossibleIDOR && p.OwnershipBoundary && p.IDLike {
			out = append(out, fmt.Sprintf("Horizontal privilege escalation possible via param: %s", name))
		}
		if p.SuspectIDOR && p.IDLike {
			out = append(out, fmt.Sprintf("Suspect IDOR surface via param: %s", name))
		}
		if p.Enumerable && p.LikelyObjectAccess {
			out = append(out, fmt.Sprintf("Object enumeration possible via param: %s", name))
		}
		if p.DebugLike {
			out = append(out, fmt.Sprintf("Debug functionality exposed via param: %s", name))
		}
		if p.TokenLike {
			out = append(out, fmt.Sprintf("Token-like parameter observed: %s", name))
		}

		// Unauthenticated access hint
		if p.IdentityAccess != nil && p.IdentityAccess["anonymous"] > 0 {
			out = append(out, fmt.Sprintf("Unauthenticated access observed (identity: anonymous) via param behavior: %s", name))
		}
	}

	// JS leaks are always findings in full report
	if len(ent.Content.JSLeaks) > 0 {
		out = append(out, fmt.Sprintf("JS leaks present: %d", len(ent.Content.JSLeaks)))
	}

	out = dedup(out)
	sort.Strings(out)
	return out
}

func deriveNextSteps(ent *knowledge.Entity) []string {
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

		if p.Enumerable {
			out = append(out, "Enumerate "+name+" sequentially")
		}
		if p.PossibleIDOR || p.SuspectIDOR {
			out = append(out, "Attempt cross-identity object access via "+name)
		}
		if p.IDLike && p.OwnershipBoundary {
			out = append(out, "Test horizontal privilege escalation using "+name)
		}
		if p.AuthBoundary && !p.OwnershipBoundary {
			out = append(out, "Test vertical privilege escalation / role boundary using "+name)
		}
		if p.TokenLike {
			out = append(out, "Attempt token reuse / swapping / fixation using "+name)
		}
		if p.DebugLike {
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

	// Ownership-phase suggestions
	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		out = append(out, "Attempt cross-user object access (IDOR) across identities")
	}

	// JS leaks suggestions
	if len(ent.Content.JSLeaks) > 0 || len(ent.Content.JSFindings) > 0 {
		out = append(out, "Review JS findings for secrets, endpoints, role gates, and client-side auth assumptions")
	}

	out = dedup(out)
	sort.Strings(out)
	return out
}
