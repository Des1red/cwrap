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

func countStatus(m map[string]int, want int) int {
	n := 0
	for _, s := range m {
		if s == want {
			n++
		}
	}
	return n
}

func (e *Engine) analyzeIDOR(
	ent *knowledge.Entity,
	responses map[string]map[string]map[string][]byte,
	statuses map[string]map[string]map[string]int,
) {
	for name, byVal := range responses {

		p := ent.Params[name]
		if p == nil || p.LikelyReflection {
			continue
		}

		anonDenied := false
		var bodies [][]byte

		for val, byIDBody := range byVal {

			// baseline must succeed to consider this value
			if statuses[name] == nil || statuses[name][val] == nil {
				continue
			}
			if statuses[name][val]["baseline"] != 200 {
				continue
			}

			// record baseline body
			body := byIDBody["baseline"]
			if len(body) == 0 {
				continue
			}

			n, err := e.int.Canonicalize(body, "")
			if err != nil {
				n = stripNumbers(body)
			}
			bodies = append(bodies, n)

			// check anonymous denial for same value (stronger signal)
			if s, ok := statuses[name][val]["anonymous"]; ok && (s == 401 || s == 403) {
				anonDenied = true
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

		if different && anonDenied {
			p.PossibleIDOR = true
			ent.Tag(knowledge.SigPossibleIDOR)
		}
	}
}

func (e *Engine) analyzeParamBehavior(ent *knowledge.Entity, responses map[string]map[string]map[string][]byte) {
	for name, byVal := range responses {

		if len(byVal) < 2 {
			continue
		}

		p := ent.Params[name]
		if p == nil {
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

			body, ok := byID["baseline"]
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
		if p == nil || !p.IDLike {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		baseline200 := 0
		anonDenied := false

		for _, byID := range byVal {

			if byID["baseline"] == 200 {
				baseline200++
			}
			if s, ok := byID["anonymous"]; ok && (s == 401 || s == 403) {
				anonDenied = true
			}
		}

		if baseline200 >= 2 && anonDenied {
			p.OwnershipBoundary = true
			p.ObservedChanges["ownership-mixed-access"] = true

			// ownership contradicts reflection, but it does NOT contradict object-access
			p.LikelyReflection = false

			ent.Tag(knowledge.SigObjectOwnership)
		}
	}
}
func (e *Engine) analyzeAuthBoundary(ent *knowledge.Entity, statuses map[string]map[string]map[string]int) {
	for name, byVal := range statuses {

		p := ent.Params[name]
		if p == nil || p.LikelyReflection {
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
