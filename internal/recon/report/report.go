package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"sort"
	"strings"
)

func Print(k *knowledge.Knowledge) {
	// deterministic order
	urls := make([]string, 0, len(k.Entities))
	for u := range k.Entities {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}
		reportEntity(ent)
	}
}

func reportEntity(ent *knowledge.Entity) {
	fmt.Println(bold + "========== Recon Report ==========" + reset)
	fmt.Println(cyan + "Target: " + reset + ent.URL)
	fmt.Println()
	reportProtocol(ent)
	reportSurface(ent)
	reportBehavior(ent)
	reportParameters(ent)
	reportSecurityModel(ent)
	reportFindings(ent)
	reportConclusion(ent)
	reportNextSteps(ent)

	fmt.Println(bold + "==================================" + reset)
}

func reportProtocol(ent *knowledge.Entity) {
	section("Protocol")

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
		info("Endpoint acts as an authentication gate")
	case hasAuth && has200:
		info("Endpoint behavior depends on identity")
	case has200 && hasOther:
		info("Endpoint returns variable response classes")
	default:
		info("Static response behavior")
	}

	switch {
	case ent.Content.LooksLikeJSON:
		info("Structured data responses detected")
	case ent.Content.LooksLikeHTML:
		info("Page-oriented responses detected")
	default:
		info("Unstructured or minimal responses")
	}

	if ent.SeenSignal(knowledge.SigStateChanging) {
		warn("Response changes based on input values")
	} else {
		good("Response deterministic for same input")
	}

	fmt.Println()
}
func reportSurface(ent *knowledge.Entity) {
	section("Surface")

	if ent.Content.LooksLikeJSON {
		info("API endpoint (JSON)")
	} else if ent.Content.LooksLikeHTML {
		info("HTML page")
	} else {
		info("Unknown content type")
	}

	if ent.HTTP.AuthLikely {
		warn("Authentication required or detected")
	} else {
		good("Public endpoint")
	}

	if ent.HTTP.CSRFPresent {
		info("CSRF protection detected")
	}

	if ent.SeenSignal(knowledge.SigStateChanging) {
		info("Stateful interaction detected")
	}

	fmt.Println()
}

func reportBehavior(ent *knowledge.Entity) {
	section("Behavior")

	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		info("Access control boundary observed")
	}

	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		info("Server enforces per-object ownership")
	}

	for name, p := range ent.Params {

		if p.IdentityAccess["anonymous"] > 0 && p.IdentityDenied["baseline"] == 0 {
			warn("Unauthenticated access affects parameter: " + name)
		}

		if p.IdentityAccess["fake-admin"] > 0 && p.IdentityDenied["anonymous"] > 0 {
			warn("Authorization influenced by client supplied role header: " + name)
		}

		if p.IdentityAccess["corrupted-token"] > 0 {
			warn("Token validation inconsistency detected on: " + name)
		}
	}

	fmt.Println()
}

func reportParameters(ent *knowledge.Entity) {
	section("Parameters")

	names := make([]string, 0, len(ent.Params))
	for n := range ent.Params {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		p := ent.Params[name]

		fmt.Print(" " + bold + name + reset)

		var tags []string

		if p.IDLike {
			tags = append(tags, "id")
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
			tags = append(tags, "object")
		}
		if p.Enumerable {
			tags = append(tags, "enumerable")
		}
		if p.AuthBoundary {
			tags = append(tags, "auth")
		}
		if p.OwnershipBoundary {
			tags = append(tags, "ownership")
		}

		if len(tags) > 0 {
			fmt.Print(" " + gray + "[" + strings.Join(tags, ", ") + "]" + reset)
		}

		fmt.Println()
	}

	fmt.Println()
}

func reportConclusion(ent *knowledge.Entity) {
	section("Conclusion")

	hasBypass := false
	hasIDOR := false

	for _, p := range ent.Params {
		if p.IdentityAccess["anonymous"] > 0 {
			hasBypass = true
		}
		if p.PossibleIDOR && p.OwnershipBoundary {
			hasIDOR = true
		}
	}

	switch {
	case hasIDOR:
		bad("Broken object-level authorization confirmed")
	case hasBypass:
		bad("Authentication enforcement inconsistent")
	case ent.SeenSignal(knowledge.SigAuthBoundary):
		good("Authorization enforced correctly")
	default:
		warn("No access control mechanisms detected")
	}

	fmt.Println()
}

func reportSecurityModel(ent *knowledge.Entity) {
	section("Security Model")

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
		info("Per-object access control (user owns resources)")
	case hasAuth && !hasObjects:
		info("Authentication gateway endpoint")
	case hasObjects && !hasOwnership:
		warn("Shared object space (multi-user data)")
	case !hasAuth && !hasObjects:
		good("Public endpoint")
	default:
		warn("Mixed authorization model")
	}

	fmt.Println()
}

func reportFindings(ent *knowledge.Entity) {
	section("Findings")

	found := false

	for name, p := range ent.Params {

		if p.PossibleIDOR && p.OwnershipBoundary {
			bad("Horizontal privilege escalation via parameter: " + name)
			found = true
		}

		if p.IdentityAccess["anonymous"] > 0 {
			bad("Authentication bypass possible via: " + name)
			found = true
		}

		if p.Enumerable && p.LikelyObjectAccess {
			warn("Object enumeration possible via: " + name)
			found = true
		}

		if p.DebugLike {
			warn("Debug functionality exposed via: " + name)
			found = true
		}
	}

	if !found {
		good("No direct vulnerabilities confirmed")
	}

	fmt.Println()
}
func reportNextSteps(ent *knowledge.Entity) {
	section("Suggested Attacks")

	for name, p := range ent.Params {

		if p.Enumerable {
			info("Enumerate " + name + " sequentially")
		}

		if p.PossibleIDOR {
			info("Attempt cross-user object access via " + name)
		}

		if p.IDLike && p.OwnershipBoundary {
			info("Test horizontal privilege escalation on " + name)
		}

		if p.AuthBoundary && !p.OwnershipBoundary {
			info("Attempt privilege escalation using " + name)
		}

		if p.TokenLike {
			info("Attempt token reuse or swapping on " + name)
		}
	}

	if ent.SeenSignal(knowledge.SigAuthBoundary) && !ent.SeenSignal(knowledge.SigObjectOwnership) {
		info("Test weak credentials")
		info("Username enumeration")
		info("Missing credential handling")
		info("Auth bypass headers (X-Forwarded-For, X-Original-URL)")
	}

	fmt.Println()
}
