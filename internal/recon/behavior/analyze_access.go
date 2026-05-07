package behavior

import "cwrap/internal/recon/knowledge"

func (e *Engine) analyzeCredentiallessIssuance(ent *knowledge.Entity) {
	isStateful := ent.SeenSignal(knowledge.SigStateChanging) ||
		ent.SessionIssued ||
		ent.HTTP.AuthLikely

	if !isStateful {
		return
	}

	for _, id := range ent.Identities {
		if id == nil {
			continue
		}
		if !id.SentCreds && id.IssuedByServer && !id.Rejected {
			ent.Tag(knowledge.SigCredentiallessTokenIssuance)
			return
		}
	}
}

func (e *Engine) analyzeOwnership(ent *knowledge.Entity, statuses map[string]map[string]map[string]int) {
	hasRealInputID := entityHasRealInputIDParam(ent)

	authIdentities := []string{}
	for idName, id := range ent.Identities {
		if isComparableIdentity(idName, id) {
			authIdentities = append(authIdentities, idName)
		}
	}

	if len(authIdentities) < 2 {
		return
	}

	for name, byVal := range statuses {
		p := ent.Params[name]
		if p == nil || p.InjectedOnly() || !p.IDLike {
			continue
		}

		if isResponseDerivedParam(p) && hasRealInputID {
			continue
		}

		mixedAccess := false

		for _, byID := range byVal {
			successCount := 0
			deniedCount := 0

			for _, idName := range authIdentities {
				switch byID[idName] {
				case 200:
					successCount++
				case 401, 403:
					deniedCount++
				}
			}

			if successCount > 0 && deniedCount > 0 {
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
		if p == nil || p.InjectedOnly() {
			continue
		}
		if isPureReflection(p) {
			continue
		}
		if p.ObservedChanges == nil {
			p.ObservedChanges = map[string]bool{}
		}

		has200 := false
		has401 := false
		has403Anon := false   // 403 from unauthenticated identity
		has403Authed := false // 403 from authenticated identity

		for _, byID := range byVal {
			for idName, status := range byID {
				id := ent.Identities[idName]
				switch status {
				case 200:
					has200 = true
				case 401:
					has401 = true
				case 403:
					if id != nil && id.SentCreds {
						if e.debug {
							println("[DEBUG] 403 authed:", idName, "SentCreds:", id.SentCreds)
						}
						has403Authed = true
					} else {
						has403Anon = true
					}
				}
			}
		}

		// auth boundary: endpoint sometimes allows access (200) and sometimes denies
		if has200 && (has401 || has403Anon) {
			p.AuthBoundary = true
			p.ObservedChanges["auth-wall-mixed-status"] = true
			ent.Tag(knowledge.SigAuthBoundary)
		}

		// role boundary: authenticated identity was denied — permission wall beyond auth
		if has403Authed {
			p.AuthBoundary = true
			p.ObservedChanges["role-wall-403-authenticated"] = true
			ent.Tag(knowledge.SigRoleBoundary)
		}
	}
}

func (e *Engine) analyzeObjectAccessSurface(
	ent *knowledge.Entity,
	statuses map[string]map[string]map[string]int,
) {
	for name, byVal := range statuses {
		p := ent.Params[name]
		if p == nil || p.InjectedOnly() || !p.IDLike {
			continue
		}

		// Only treat real inputs as primary object-access surfaces.
		if !isRealInputParam(p) {
			continue
		}

		byIdentitySuccess := map[string]int{}
		byIdentityDenied := map[string]int{}

		for _, byID := range byVal {
			for idName, status := range byID {
				id := ent.Identities[idName]
				if !isComparableIdentity(idName, id) {
					continue
				}

				switch status {
				case 200:
					byIdentitySuccess[idName]++
				case 401, 403:
					byIdentityDenied[idName]++
				}
			}
		}

		for idName := range byIdentitySuccess {
			if byIdentitySuccess[idName] > 0 && byIdentityDenied[idName] > 0 {
				p.LikelyObjectAccess = true
				p.AuthBoundary = true
				p.SuspectIDOR = true
				p.ObservedChanges["single-identity-object-access-control"] = true

				if !p.ObservedChanges["interest+object-access-control"] {
					p.Interest += 2
					p.ObservedChanges["interest+object-access-control"] = true
					if p.Interest > 5 {
						p.Interest = 5
					}
				}
				return
			}
		}
	}
}
