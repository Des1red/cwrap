package behavior

import (
	"bytes"
	"cwrap/internal/recon/knowledge"
)

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

		normalized := make([][]byte, 0, len(byVal))

		for _, byID := range byVal {

			body, ok := pickCredBody(ent, byID, nil)
			if !ok || len(body) == 0 {
				continue
			}

			n, err := e.int.Canonicalize(body, name)
			if err != nil {
				p.LikelyReflection = false
				p.LikelyObjectAccess = true
				p.ObservedChanges["format-opaque"] = true

				if !p.ObservedChanges["interest+object"] {
					p.Interest += 2
					p.ObservedChanges["interest+object"] = true
					if p.Interest > 5 {
						p.Interest = 5
					}
				}
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

		hasStrongEvidence :=
			p.LikelyObjectAccess ||
				p.Enumerable ||
				p.AuthBoundary ||
				p.OwnershipBoundary ||
				p.PossibleIDOR ||
				p.SuspectIDOR ||
				p.ObservedChanges["structure-changes"] ||
				p.ObservedChanges["idor-raw-diff"] ||
				p.ObservedChanges["idor-structure-diff"]

		if allSame {
			// Stable structure is weak evidence. Keep it as history only if there
			// is no stronger object/access/security evidence.
			if !hasStrongEvidence {
				p.LikelyReflection = true
				p.ObservedChanges["stable-structure"] = true

				if !p.ObservedChanges["interest+reflect"] {
					p.Interest += 1
					p.ObservedChanges["interest+reflect"] = true
					if p.Interest > 5 {
						p.Interest = 5
					}
				}
			}
			continue
		}

		// Structural difference is stronger than reflection.
		p.LikelyReflection = false
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

		if added && p.Interest > 5 {
			p.Interest = 5
		}
	}
}
