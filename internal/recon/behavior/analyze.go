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

func (e *Engine) analyzeIDOR(ent *knowledge.Entity, responses map[string]map[string][]byte, statuses map[string]map[string]int) {

	for name, variations := range responses {

		p := ent.Params[name]
		if p == nil || p.LikelyReflection {
			continue
		}

		// collect successful responses
		var bodies [][]byte

		for val, body := range variations {
			if statuses[name][val] == 200 {
				n, err := e.int.Canonicalize(body, "")
				if err != nil {
					n = stripNumbers(body)
				}
				bodies = append(bodies, n)
			}
		}

		if len(bodies) < 2 {
			continue
		}

		// compare 200 responses
		first := bodies[0]
		different := false

		for i := 1; i < len(bodies); i++ {
			if !bytes.Equal(first, bodies[i]) {
				different = true
				break
			}
		}

		if different {
			p.PossibleIDOR = true
			ent.Tag(knowledge.SigPossibleIDOR)
		}
	}
}

func (e *Engine) analyzeOwnership(ent *knowledge.Entity, statuses map[string]map[string]int) {
	for name, variations := range statuses {
		p := ent.Params[name]
		if p == nil || !p.IDLike {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		has200 := 0
		hasDenied := false

		for _, s := range variations {
			if s == 200 {
				has200++
			}
			if s == 401 || s == 403 {
				hasDenied = true
			}
		}
		if has200 >= 2 && hasDenied {
			p.OwnershipBoundary = true
			p.ObservedChanges["ownership-mixed-access"] = true

			// ownership contradicts reflection, but it does NOT contradict object-access
			p.LikelyReflection = false

			ent.Tag(knowledge.SigObjectOwnership)
		}
	}
}

func (e *Engine) analyzeParamBehavior(ent *knowledge.Entity, responses map[string]map[string][]byte) {
	for name, variations := range responses {
		if len(variations) < 2 {
			continue
		}

		p := ent.Params[name]
		if p == nil {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		// reset flags each analysis pass
		p.LikelyReflection = false
		p.LikelyObjectAccess = false
		p.Enumerable = false

		normalized := make([][]byte, 0, len(variations))
		for _, body := range variations {
			n, err := e.int.Canonicalize(body, name)
			if err != nil {
				p.LikelyObjectAccess = true
				p.ObservedChanges["format-opaque"] = true
				break
			}
			normalized = append(normalized, n)
		}

		if len(normalized) == 0 {
			continue
		}

		// ---- reflection vs object-access ----
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

		// ---- enumeration detection (unique bodies) ----
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

func (e *Engine) analyzeAuthBoundary(ent *knowledge.Entity, statuses map[string]map[string]int) {
	for name, variations := range statuses {
		p := ent.Params[name]
		if p == nil || p.LikelyReflection {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		has200 := false
		hasDenied := false

		for _, s := range variations {
			if s == 200 {
				has200 = true
			}
			if s == 401 || s == 403 {
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
