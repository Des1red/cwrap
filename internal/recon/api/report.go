package api

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"sort"
	"strings"
)

func (e *Engine) reportEntity(url string) {
	ent := e.k.Entity(url)

	fmt.Println("========== Recon Report ==========")
	fmt.Println("Target:", url)
	fmt.Println()
	e.reportProtocol(ent)
	e.reportSurface(ent)
	e.reportBehavior(ent)
	e.reportParameters(ent)
	e.reportSecurityModel(ent)
	e.reportFindings(ent)
	e.reportConclusion(ent)
	e.reportNextSteps(ent)

	fmt.Println("==================================")
}

func (e *Engine) reportProtocol(ent *knowledge.Entity) {
	fmt.Println("[Protocol]")

	// ---- response class ----
	has200 := false
	hasAuth := false
	hasOther := false

	for code := range ent.Content.Statuses {
		switch code {
		case 200:
			has200 = true
		case 401, 403:
			hasAuth = true
		default:
			hasOther = true
		}
	}

	switch {
	case hasAuth && !has200:
		fmt.Println(" Endpoint acts as an authentication gate")
	case hasAuth && has200:
		fmt.Println(" Endpoint behavior depends on identity")
	case has200 && hasOther:
		fmt.Println(" Endpoint returns variable response classes")
	default:
		fmt.Println(" Static response behavior")
	}

	// ---- content nature ----
	switch {
	case ent.Content.LooksLikeJSON:
		fmt.Println(" Structured data responses detected")
	case ent.Content.LooksLikeHTML:
		fmt.Println(" Page-oriented responses detected")
	default:
		fmt.Println(" Unstructured or minimal responses")
	}

	// ---- determinism ----
	if ent.SeenSignal(knowledge.SigStateChanging) {
		fmt.Println(" Response changes based on input values")
	} else {
		fmt.Println(" Response deterministic for same input")
	}

	fmt.Println()
}

func (e *Engine) reportSurface(ent *knowledge.Entity) {
	fmt.Println("[Surface]")

	if ent.Content.LooksLikeJSON {
		fmt.Println(" Type: API endpoint (JSON)")
	} else if ent.Content.LooksLikeHTML {
		fmt.Println(" Type: HTML page")
	} else {
		fmt.Println(" Type: Unknown content")
	}

	if ent.HTTP.AuthLikely {
		fmt.Println(" Authentication: Required or detected")
	} else {
		fmt.Println(" Authentication: Not required / public")
	}

	if ent.HTTP.CSRFPresent {
		fmt.Println(" CSRF Protection: Present")
	}

	if ent.SeenSignal(knowledge.SigStateChanging) {
		fmt.Println(" Behavior: Stateful interaction detected")
	}

	fmt.Println()
}

func (e *Engine) reportBehavior(ent *knowledge.Entity) {
	fmt.Println("[Behavior]")

	if ent.SeenSignal(knowledge.SigHasJSONBody) {
		fmt.Println(" Structured responses vary with input")
	}

	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		fmt.Println(" Access control boundary observed")
	}

	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		fmt.Println(" Object ownership checks exist")
	}

	fmt.Println()
}

func (e *Engine) reportParameters(ent *knowledge.Entity) {
	fmt.Println("[Parameters]")

	names := make([]string, 0, len(ent.Params))
	for n := range ent.Params {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		p := ent.Params[name]

		fmt.Print(" -", name)

		// -------- classification tags --------
		var tags []string

		if p.IDLike {
			tags = append(tags, "id-like")
		}
		if p.TokenLike {
			tags = append(tags, "token")
		}
		if p.DebugLike {
			tags = append(tags, "debug")
		}
		if p.LikelyReflection {
			tags = append(tags, "reflection")
		}
		if p.LikelyObjectAccess {
			tags = append(tags, "object-access")
		}
		if p.Enumerable {
			tags = append(tags, "enumerable")
		}
		if p.AuthBoundary {
			tags = append(tags, "auth-boundary")
		}
		if p.OwnershipBoundary {
			tags = append(tags, "ownership")
		}
		if p.PossibleIDOR {
			tags = append(tags, "POTENTIAL-IDOR")
		}

		if len(tags) > 0 {
			fmt.Print(" [", strings.Join(tags, ", "), "]")
		}

		// -------- semantic evidence (NOT debug state) --------
		var evidence []string

		if p.OwnershipBoundary {
			evidence = append(evidence, "access differs between identities")
		}

		if p.LikelyObjectAccess {
			evidence = append(evidence, "object returned depends on parameter value")
		}

		if p.Enumerable {
			evidence = append(evidence, "sequential object space detected")
		}

		if p.LikelyReflection {
			evidence = append(evidence, "parameter reflected but not controlling object")
		}

		if p.AuthBoundary && !p.OwnershipBoundary {
			evidence = append(evidence, "authorization gate affects response")
		}

		if p.PossibleIDOR {
			evidence = append(evidence, "distinct objects returned without ownership enforcement")
		}

		if len(evidence) > 0 {
			fmt.Print(" {", strings.Join(evidence, ", "), "}")
		}

		fmt.Println()
	}

	fmt.Println()
}

func (e *Engine) reportConclusion(ent *knowledge.Entity) {
	fmt.Println("[Conclusion]")

	switch {
	case ent.SeenSignal(knowledge.SigObjectOwnership):
		fmt.Println(" Target exposes user-isolated resources. Focus: horizontal access.")

	case ent.SeenSignal(knowledge.SigAuthBoundary) && !ent.SeenSignal(knowledge.SigObjectOwnership):
		fmt.Println(" Target controls authentication. Focus: identity manipulation.")

	case ent.SeenSignal(knowledge.SigStateChanging):
		fmt.Println(" Target reacts to input statefully. Focus: workflow abuse.")

	default:
		fmt.Println(" Target appears passive. Focus: discovery and fuzzing.")
	}

	fmt.Println()
}
func (e *Engine) reportSecurityModel(ent *knowledge.Entity) {
	fmt.Println("[Security Model]")

	hasOwnership := false
	hasAuth := false
	hasObjects := false

	for _, p := range ent.Params {
		if p.OwnershipBoundary {
			hasOwnership = true
		}
		if p.AuthBoundary {
			hasAuth = true
		}
		if p.LikelyObjectAccess {
			hasObjects = true
		}
	}

	switch {
	case hasOwnership:
		fmt.Println(" Per-object access control (user owns resources)")

	case hasAuth && !hasObjects:
		fmt.Println(" Authentication gateway endpoint")

	case hasObjects && !hasOwnership:
		fmt.Println(" Shared object space (multi-user data)")

	case !hasAuth && !hasObjects:
		fmt.Println(" Public endpoint")

	default:
		fmt.Println(" Role-based or mixed authorization")
	}

	fmt.Println()
}

func (e *Engine) reportFindings(ent *knowledge.Entity) {
	fmt.Println("[Findings]")

	found := false

	for name, p := range ent.Params {
		if p.IDLike && p.OwnershipBoundary {
			fmt.Println(" Potential IDOR surface via parameter:", name)
			found = true
		}

		if p.PossibleIDOR {
			fmt.Println(" IDOR candidate via parameter:", name)
			found = true
		}

		if p.Enumerable && p.LikelyObjectAccess {
			fmt.Println(" Object enumeration possible via:", name)
			found = true
		}

		if p.DebugLike {
			fmt.Println(" Debug functionality exposed:", name)
			found = true
		}
	}

	if !found {
		fmt.Println(" No direct vulnerabilities detected yet")
	}

	fmt.Println()
}

func (e *Engine) reportNextSteps(ent *knowledge.Entity) {
	fmt.Println("[Suggested Attacks]")

	for name, p := range ent.Params {

		if p.Enumerable {
			fmt.Println(" Enumerate", name, "sequentially")
		}

		if p.PossibleIDOR {
			fmt.Println(" Try accessing other users' objects via", name)
		}
		if p.IDLike && p.OwnershipBoundary {
			fmt.Println(" Try accessing other numeric IDs on", name)
			fmt.Println(" Test horizontal privilege escalation")
		}
		if p.AuthBoundary && !p.OwnershipBoundary {
			fmt.Println(" Attempt privilege escalation using", name)
		}

		if p.TokenLike {
			fmt.Println(" Attempt token reuse / swapping on", name)
		}
	}
	// auth gateway logic
	onlyAuth := ent.SeenSignal(knowledge.SigAuthBoundary) && !ent.SeenSignal(knowledge.SigObjectOwnership)

	if onlyAuth {
		fmt.Println(" Attempt credential brute-force / weak password testing")
		fmt.Println(" Test username enumeration via response differences")
		fmt.Println(" Try missing/blank credentials")
		fmt.Println(" Check for auth bypass headers (X-Forwarded-For, X-Original-URL)")
	}

	fmt.Println()
}
