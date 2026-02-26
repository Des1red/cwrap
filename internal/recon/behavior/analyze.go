package behavior

import (
	"bytes"
	"cwrap/internal/recon/knowledge"
)

// fallback for non-JSON responses: strip numbers to get a rough structural diff
func stripNumbers(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	for i := range out {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = '#'
		}
	}
	return out
}

func anyStatusIs(m map[string]int, want ...int) bool {
	for _, s := range m {
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
}

// ---------- identity-agnostic helpers ----------

// pick a "credentialed" body for this value (prefer a cred identity that succeeded)
func pickCredBody(ent *knowledge.Entity, bodies map[string][]byte, statuses map[string]int) ([]byte, bool) {
	for idName, body := range bodies {
		id := ent.Identities[idName]
		if id == nil || !id.SentCreds {
			continue
		}
		if statuses != nil && statuses[idName] != 200 {
			continue
		}
		if len(body) == 0 {
			continue
		}
		return body, true
	}
	// fallback: any cred body (even if status map missing)
	for idName, body := range bodies {
		id := ent.Identities[idName]
		if id == nil || !id.SentCreds {
			continue
		}
		if len(body) == 0 {
			continue
		}
		return body, true
	}
	return nil, false
}

func anyNoCredDenied(ent *knowledge.Entity, byID map[string]int) bool {
	for idName, s := range byID {
		id := ent.Identities[idName]
		if id == nil {
			continue
		}
		if !id.SentCreds && (s == 401 || s == 403) {
			return true
		}
	}
	return false
}

func anyCredStatus(ent *knowledge.Entity, byID map[string]int, want ...int) bool {
	for idName, s := range byID {
		id := ent.Identities[idName]
		if id == nil || !id.SentCreds {
			continue
		}
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
}

func countCredStatus(ent *knowledge.Entity, byID map[string]int, want int) int {
	n := 0
	for idName, s := range byID {
		id := ent.Identities[idName]
		if id == nil || !id.SentCreds {
			continue
		}
		if s == want {
			n++
		}
	}
	return n
}

// ---------- analyzers ----------

func (e *Engine) analyzeIDOR(
	ent *knowledge.Entity,
	responses map[string]map[string]map[string][]byte,
	statuses map[string]map[string]map[string]int,
) {
	for name, byVal := range responses {

		p := ent.Params[name]
		if p == nil || p.InjectedOnly() || p.LikelyReflection {
			continue
		}

		noCredDenied := false
		var bodies [][]byte

		for val, byIDBody := range byVal {

			// need statuses for this param/value to reason about auth
			if statuses[name] == nil || statuses[name][val] == nil {
				continue
			}
			byIDStatus := statuses[name][val]

			// require at least one credentialed success for this value
			if !anyCredStatus(ent, byIDStatus, 200) {
				continue
			}

			// choose a credentialed body for structural comparison
			body, ok := pickCredBody(ent, byIDBody, byIDStatus)
			if !ok || len(body) == 0 {
				continue
			}

			n, err := e.int.Canonicalize(body, "")
			if err != nil {
				n = stripNumbers(body)
			}
			bodies = append(bodies, n)

			// stronger signal: no-cred denied for same value
			if anyNoCredDenied(ent, byIDStatus) {
				noCredDenied = true
			}
		}

		if len(bodies) < 2 {
			continue
		}

		first := bodies[0]
		different := false
		for i := 1; i < len(bodies); i++ {
			if !bytes.Equal(first, bodies[i]) {
				different = true
				break
			}
		}

		if different {
			p.ObservedChanges["idor-structure-diff"] = true

			// escalate only if a no-cred identity is denied too
			if noCredDenied {
				p.PossibleIDOR = true
				ent.Tag(knowledge.SigPossibleIDOR)
			}
		}
	}
}

func (e *Engine) analyzeParamBehavior(ent *knowledge.Entity, responses map[string]map[string]map[string][]byte) {
	for name, byVal := range responses {

		if len(byVal) < 2 {
			continue
		}

		p := ent.Params[name]
		if p == nil || p.InjectedOnly() {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		p.LikelyReflection = false
		p.LikelyObjectAccess = false
		p.Enumerable = false

		normalized := make([][]byte, 0, len(byVal))

		for _, byID := range byVal {

			body, ok := pickCredBody(ent, byID, nil)
			if !ok || len(body) == 0 {
				continue
			}

			n, err := e.int.Canonicalize(body, name)
			if err != nil {
				p.LikelyObjectAccess = true
				p.ObservedChanges["format-opaque"] = true
				break
			}
			normalized = append(normalized, n)
		}

		if len(normalized) < 2 {
			continue
		}

		base := normalized[0]
		allSame := true
		for i := 1; i < len(normalized); i++ {
			if !bytes.Equal(base, normalized[i]) {
				allSame = false
				break
			}
		}

		if allSame {
			p.LikelyReflection = true
			p.ObservedChanges["stable-structure"] = true
			continue
		}

		p.LikelyObjectAccess = true
		p.ObservedChanges["structure-changes"] = true

		uniq := map[string]bool{}
		for _, b := range normalized {
			uniq[string(b)] = true
		}
		if len(uniq) >= 3 {
			p.Enumerable = true
			p.ObservedChanges["enumerable-structure-space"] = true
		}
	}
}

func (e *Engine) analyzeOwnership(ent *knowledge.Entity, statuses map[string]map[string]map[string]int) {
	for name, byVal := range statuses {

		p := ent.Params[name]
		if p == nil || p.InjectedOnly() || !p.IDLike {
			continue
		}

		authIdentities := []string{}

		for idName, id := range ent.Identities {
			if id != nil && id.SentCreds && !id.Rejected {
				authIdentities = append(authIdentities, idName)
			}
		}

		// Need at least 2 authenticated identities to prove ownership
		if len(authIdentities) < 2 {
			continue
		}

		mixedAccess := false

		for _, byID := range byVal {
			successCount := 0
			for _, idName := range authIdentities {
				if byID[idName] == 200 {
					successCount++
				}
			}
			if successCount > 0 && successCount < len(authIdentities) {
				mixedAccess = true
				break
			}
		}

		if mixedAccess {
			p.OwnershipBoundary = true
			ent.Tag(knowledge.SigObjectOwnership)
		}
	}
}

func (e *Engine) analyzeAuthBoundary(ent *knowledge.Entity, statuses map[string]map[string]map[string]int) {
	for name, byVal := range statuses {

		p := ent.Params[name]
		if p == nil || p.InjectedOnly() || p.LikelyReflection {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		has200 := false
		hasDenied := false

		for _, byID := range byVal {
			if anyStatusIs(byID, 200) {
				has200 = true
			}
			if anyStatusIs(byID, 401, 403) {
				hasDenied = true
			}
		}

		if has200 && hasDenied {
			p.AuthBoundary = true
			p.ObservedChanges["auth-wall-mixed-status"] = true
			ent.Tag(knowledge.SigAuthBoundary)
		}
	}
}
