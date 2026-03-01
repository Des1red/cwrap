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

		// canonicalized bodies (strong structural diff)
		var canonBodies [][]byte

		// raw fingerprint bodies (weak diff)
		rawFPs := map[string]bool{}

		for val, byIDBody := range byVal {

			if statuses[name] == nil || statuses[name][val] == nil {
				continue
			}
			byIDStatus := statuses[name][val]

			// require at least one credentialed success
			if !anyCredStatus(ent, byIDStatus, 200) {
				continue
			}

			body, ok := pickCredBody(ent, byIDBody, byIDStatus)
			if !ok || len(body) == 0 {
				continue
			}

			// --- RAW fingerprint tracking (weak signal)
			rawFPs[fpString(200, body)] = true

			// --- Canonicalized structural diff (strong signal)
			n, err := e.int.Canonicalize(body, "")
			if err != nil {
				n = stripNumbers(body)
			}
			canonBodies = append(canonBodies, n)

			if anyNoCredDenied(ent, byIDStatus) {
				noCredDenied = true
			}
		}

		// --- WEAK IDOR SIGNAL ---
		// If credentialed responses differ for different values
		if len(rawFPs) >= 2 && noCredDenied && p.IDLike {
			p.SuspectIDOR = true
			p.ObservedChanges["idor-raw-diff"] = true
		}

		// --- STRONG IDOR SIGNAL ---
		if len(canonBodies) < 2 {
			continue
		}

		first := canonBodies[0]
		structDiff := false

		for i := 1; i < len(canonBodies); i++ {
			if !bytes.Equal(first, canonBodies[i]) {
				structDiff = true
				break
			}
		}

		if structDiff {
			p.ObservedChanges["idor-structure-diff"] = true

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

			p.Interest += 1
			if p.Interest > 5 {
				p.Interest = 5
			}
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
		added := false
		if p.LikelyObjectAccess && !p.ObservedChanges["interest+object"] {
			p.Interest += 2
			p.ObservedChanges["interest+object"] = true
			added = true
		}
		if p.Enumerable && !p.ObservedChanges["interest+enum"] {
			p.Interest += 2
			p.ObservedChanges["interest+enum"] = true
			added = true
		}
		if p.LikelyReflection && !p.ObservedChanges["interest+reflect"] {
			p.Interest += 1
			p.ObservedChanges["interest+reflect"] = true
			added = true
		}
		if added && p.Interest > 5 {
			p.Interest = 5
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
