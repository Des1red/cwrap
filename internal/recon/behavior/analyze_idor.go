package behavior

import (
	"bytes"
	"cwrap/internal/recon/canonicalize"
	"cwrap/internal/recon/knowledge"
)

func (e *Engine) analyzeIDOR(
	ent *knowledge.Entity,
	responses map[string]map[string]map[string][]byte,
	statuses map[string]map[string]map[string]int,
) {
	hasRealInputID := entityHasRealInputIDParam(ent)
	for name, byVal := range responses {

		p := ent.Params[name]
		if p == nil || p.InjectedOnly() {
			continue
		}
		if isPureReflection(p) {
			continue
		}

		// JSON-only response fields are supporting evidence.
		// Do not promote them to IDOR when a controllable ID-like param exists.
		responseDerived := isResponseDerivedParam(p)
		allowPrimaryIDOR := !responseDerived || !hasRealInputID

		credDenied := false

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
				n = canonicalize.StripNumbers(body)
			}
			canonBodies = append(canonBodies, n)

			// ownership IDOR: some cred identities allowed, others denied on this same value
			if anyCredStatus(ent, byIDStatus, 200) &&
				(anyCredStatus(ent, byIDStatus, 403) || anyCredStatus(ent, byIDStatus, 401)) {
				credDenied = true
			}
		}

		// --- WEAK IDOR SIGNAL ---
		// If credentialed responses differ for different values
		if len(rawFPs) >= 2 && credDenied && p.IDLike && allowPrimaryIDOR {
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
			if credDenied && allowPrimaryIDOR {
				p.ObservedChanges["idor-structure-diff"] = true
				p.PossibleIDOR = true
				ent.Tag(knowledge.SigPossibleIDOR)
			}
		}

		// --- OWNERSHIP IDOR (no structural diff needed, ownership already proven) ---
		if p.OwnershipBoundary && p.IDLike && allowPrimaryIDOR {
			if credDenied || p.LikelyObjectAccess || p.ObservedChanges["structure-changes"] {
				p.PossibleIDOR = true
				ent.Tag(knowledge.SigPossibleIDOR)
			}
		}
	}
}
