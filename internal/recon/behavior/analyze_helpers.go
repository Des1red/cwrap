package behavior

import "cwrap/internal/recon/knowledge"

// ---------- identity-agnostic helpers ----------

func isComparableIdentity(name string, id *knowledge.Identity) bool {
	if id == nil || !id.SentCreds {
		return false
	}
	if name == knowledge.LiveSession {
		return false
	}
	return true
}

func anyCredStatus(ent *knowledge.Entity, byID map[string]int, want ...int) bool {
	for idName, s := range byID {
		id := ent.Identities[idName]
		if !isComparableIdentity(idName, id) {
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

func isPureReflection(p *knowledge.ParamIntel) bool {
	return p.LikelyReflection &&
		!p.LikelyObjectAccess &&
		!p.AuthBoundary &&
		!p.OwnershipBoundary &&
		!p.PossibleIDOR &&
		!p.SuspectIDOR
}

func isRealInputParam(p *knowledge.ParamIntel) bool {
	if p == nil {
		return false
	}

	return p.Sources[knowledge.ParamQuery] ||
		p.Sources[knowledge.ParamPath] ||
		p.Sources[knowledge.ParamForm]
}

func isResponseDerivedParam(p *knowledge.ParamIntel) bool {
	if p == nil {
		return false
	}

	return p.Sources[knowledge.ParamJSON] && !isRealInputParam(p)
}
func entityHasRealInputIDParam(ent *knowledge.Entity) bool {
	if ent == nil {
		return false
	}

	for _, p := range ent.Params {
		if p == nil {
			continue
		}
		if p.IDLike && isRealInputParam(p) {
			return true
		}
	}

	return false
}

// pick a "credentialed" body for this value (prefer a cred identity that succeeded)
func pickCredBody(ent *knowledge.Entity, bodies map[string][]byte, statuses map[string]int) ([]byte, bool) {
	for idName, body := range bodies {
		id := ent.Identities[idName]
		if !isComparableIdentity(idName, id) {
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
		if !isComparableIdentity(idName, id) {
			continue
		}
		if len(body) == 0 {
			continue
		}
		return body, true
	}
	return nil, false
}

func demoteResponseDerivedIDORIfRealInputExists(ent *knowledge.Entity) {
	if !entityHasRealInputIDParam(ent) {
		return
	}

	for _, p := range ent.Params {
		if p == nil {
			continue
		}

		if isResponseDerivedParam(p) {
			p.PossibleIDOR = false
			p.SuspectIDOR = false
			p.OwnershipBoundary = false
		}
	}
}

func promoteRealInputIDOverResponseID(ent *knowledge.Entity) {
	if ent == nil {
		return
	}

	var realInputs []*knowledge.ParamIntel
	var responseDerived []*knowledge.ParamIntel

	for _, p := range ent.Params {
		if p == nil || !p.IDLike {
			continue
		}

		if isRealInputParam(p) {
			realInputs = append(realInputs, p)
			continue
		}

		if isResponseDerivedParam(p) {
			responseDerived = append(responseDerived, p)
		}
	}

	if len(realInputs) == 0 || len(responseDerived) == 0 {
		return
	}

	responseHasOwnership := false
	responseHasIDOR := false
	responseHasSuspect := false

	for _, p := range responseDerived {
		if p.OwnershipBoundary {
			responseHasOwnership = true
		}
		if p.PossibleIDOR {
			responseHasIDOR = true
		}
		if p.SuspectIDOR {
			responseHasSuspect = true
		}
	}

	if !responseHasOwnership && !responseHasIDOR && !responseHasSuspect {
		return
	}

	for _, p := range realInputs {
		if !p.LikelyObjectAccess && !p.AuthBoundary && !p.ObservedChanges["structure-changes"] {
			continue
		}

		if responseHasOwnership {
			p.OwnershipBoundary = true
			p.ObservedChanges["ownership-via-response-id"] = true
		}

		if responseHasIDOR {
			p.PossibleIDOR = true
			p.ObservedChanges["idor-via-real-input-id"] = true
		}

		if responseHasSuspect {
			p.SuspectIDOR = true
			p.ObservedChanges["suspect-idor-via-real-input-id"] = true
		}
	}

	for _, p := range responseDerived {
		p.OwnershipBoundary = false
		p.PossibleIDOR = false
		p.SuspectIDOR = false
	}
}
