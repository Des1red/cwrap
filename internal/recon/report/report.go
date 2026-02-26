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
		reportGraph(ent, k)
	}
}

func hasValidIdentity(ent *knowledge.Entity) bool {
	for _, id := range ent.Identities {
		if id.Kind == knowledge.IdentityUser && !id.Rejected {
			return true
		}
	}
	return false
}

func reportEntity(ent *knowledge.Entity) {
	fmt.Println(bold + "========== Recon Report ==========" + reset)
	fmt.Println(cyan + "Target: " + reset + ent.URL)
	fmt.Println()
	validIdentity := hasValidIdentity(ent)
	reportProtocol(ent)
	reportSurface(ent, validIdentity)
	reportSession(ent)
	reportIdentities(ent)
	reportBehavior(ent)
	reportParameters(ent)
	reportSecurityModel(ent)
	reportFindings(ent)
	reportJS(ent)
	reportConclusion(ent, validIdentity)
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
		if ent.HTTP.AuthLikely {
			info("Endpoint requires authentication")
		} else {
			info("Endpoint acts as an authentication gate")
		}
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
func reportSurface(ent *knowledge.Entity, validIdentity bool) {
	section("Surface")

	if ent.Content.LooksLikeJSON {
		info("API endpoint (JSON)")
	} else if ent.Content.LooksLikeHTML {
		info("HTML page")
	} else {
		info("Unknown content type")
	}

	if validIdentity {
		good("Authenticated session active")
	} else if ent.HTTP.AuthLikely {
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

func reportSession(ent *knowledge.Entity) {

	if len(ent.SessionCookies) == 0 {
		return
	}

	section("Session")

	if ent.SessionUsed {
		info("Reused stored session")
	}

	if ent.SessionIssued {
		info("Server issued or rotated session")
	}

	for name := range ent.SessionCookies {
		fmt.Println(" • Cookie:", name)
	}

	fmt.Println()
}

func reportIdentities(ent *knowledge.Entity) {
	section("Identities")

	if len(ent.IdentityIndex) == 0 {
		info("No identity mechanisms observed")
		fmt.Println()
		return
	}

	// Detect if we have a valid primary identity
	hasPrimary := false
	for _, id := range ent.IdentityIndex {
		if id.Kind == knowledge.IdentityUser && !id.Rejected {
			hasPrimary = true
			break
		}
	}

	printed := 0

	for _, id := range ent.IdentityIndex {

		//  If a valid primary exists, suppress rejected identities
		if hasPrimary && id.Rejected {
			continue
		}

		printed++

		label := identityLabel(id)
		fmt.Print(" " + bold + label + reset)

		var traits []string

		if id.IssuedByServer {
			traits = append(traits, "issued")
		}
		if len(id.CookieNames) > 0 {
			traits = append(traits, "cookies:"+strings.Join(id.CookieNames, ","))
		}
		if id.AuthScheme != "" {
			traits = append(traits, id.AuthScheme)
		}
		if id.HasCSRF {
			traits = append(traits, "csrf")
		}
		if id.Rotates {
			traits = append(traits, "rotating")
		}
		if id.Role != "" {
			traits = append(traits, "role:"+id.Role)
		}

		// If no primary exists, show rejected identities
		if !hasPrimary && id.Rejected {
			traits = []string{"rejected"}
		}

		if len(traits) > 0 {
			fmt.Print(" " + gray + "[" + strings.Join(traits, ", ") + "]" + reset)
		}

		fmt.Println()
	}

	if printed == 0 {
		info("No identity mechanisms observed")
	}

	fmt.Println()
}

func identityLabel(id *knowledge.Identity) string {
	switch id.Kind {
	case knowledge.IdentityNone:
		return "no-credentials"
	case knowledge.IdentityBootstrap:
		return "bootstrap-session"
	case knowledge.IdentityInvalid:
		return "invalid-credentials"
	case knowledge.IdentityUser:
		if !id.Effective {
			return "presented-credentials"
		}
		return "authenticated-user"
	case knowledge.IdentityElevated:
		return "elevated-user"
	default:
		return "identity"
	}
}
func reportBehavior(ent *knowledge.Entity) {

	var lines []func()

	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		lines = append(lines, func() {
			info("Access control boundary observed")
		})
	}

	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		lines = append(lines, func() {
			info("Server enforces per-object ownership")
		})
	}

	for name, p := range ent.Params {

		if p.InjectedOnly() {
			continue
		}

		var noCredAccess int
		var credDenied int

		for idName, access := range p.IdentityAccess {
			id := ent.Identities[idName]
			if id == nil {
				continue
			}
			if !id.SentCreds {
				noCredAccess += access
			}
		}

		for idName, denied := range p.IdentityDenied {
			id := ent.Identities[idName]
			if id == nil {
				continue
			}
			if id.SentCreds {
				credDenied += denied
			}
		}

		if noCredAccess > 0 && credDenied > 0 {
			paramName := name
			lines = append(lines, func() {
				warn("Unauthenticated access possible via parameter: " + paramName)
			})
		}

		for _, id := range ent.Identities {
			if id.SentCreds && id.Effective {
				paramName := name
				lines = append(lines, func() {
					info("Identity influences behavior on parameter: " + paramName)
				})
				break
			}
		}
	}

	if len(lines) == 0 {
		return
	}

	section("Behavior")

	for _, l := range lines {
		l()
	}

	fmt.Println()
}

func reportParameters(ent *knowledge.Entity) {

	// Collect printable params
	names := make([]string, 0, len(ent.Params))
	for name, p := range ent.Params {
		if p.InjectedOnly() {
			continue
		}
		names = append(names, name)
	}

	if len(names) == 0 {
		return
	}

	sort.Strings(names)

	section("Parameters")

	for _, name := range names {
		p := ent.Params[name]

		if p.InjectedOnly() {
			continue
		}
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

func reportConclusion(ent *knowledge.Entity, validIdentity bool) {
	section("Conclusion")

	hasBypass := false
	hasIDOR := false

	for _, p := range ent.Params {

		for idName, access := range p.IdentityAccess {
			id := ent.Identities[idName]
			if id == nil {
				continue
			}
			if !id.SentCreds && access > 0 {
				hasBypass = true
			}
		}
	}
	hasIdentityAuth := ent.HTTP.AuthLikely
	hasBootstrap := false
	hasElevated := false

	for _, id := range ent.Identities {
		if id.Kind == knowledge.IdentityBootstrap {
			hasBootstrap = true
		}
		if id.Kind == knowledge.IdentityElevated {
			hasElevated = true
		}
		if id.AuthScheme != "" || len(id.CookieNames) > 0 {
			hasIdentityAuth = true
		}
	}
	hasSuspect := false
	for _, p := range ent.Params {
		if p.SuspectIDOR {
			hasSuspect = true
			break
		}
	}
	switch {
	case hasIDOR:
		bad("Broken object-level authorization confirmed")
	case hasBypass:
		bad("Authentication enforcement inconsistent")
	case hasIDOR:
		bad("Broken object-level authorization confirmed")
	case hasSuspect:
		warn("Possible broken object-level authorization (needs additional identities to confirm)")
	case validIdentity && ent.SeenSignal(knowledge.SigAuthBoundary):
		good("Authenticated and authorization enforced correctly")
	case validIdentity:
		good("Authenticated session established")
	case hasBootstrap || hasElevated || hasIdentityAuth:
		good("Authentication mechanisms detected")
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
	hasIdentityAuth := ent.HTTP.AuthLikely
	hasBootstrap := false
	hasElevated := false

	for _, id := range ent.Identities {
		if id.Kind == knowledge.IdentityBootstrap {
			hasBootstrap = true
		}
		if id.Kind == knowledge.IdentityElevated {
			hasElevated = true
		}
		if id.AuthScheme != "" || len(id.CookieNames) > 0 {
			hasIdentityAuth = true
		}
	}
	switch {
	case hasBootstrap:
		info("Authentication bootstrap endpoint")

	case hasElevated:
		warn("Privilege-bearing session issued (elevated role)")

	case hasAuth || hasIdentityAuth:
		if ent.SeenSignal(knowledge.SigAuthBoundary) {
			info("Protected resource (authentication required)")
		} else {
			info("Authentication gateway endpoint")
		}
	case hasOwnership:
		info("Per-object access control (user owns resources)")
	case hasObjects && !hasOwnership:
		warn("Shared object space (multi-user data)")
	default:
		good("Public endpoint")
	}

	fmt.Println()
}

func reportFindings(ent *knowledge.Entity) {
	section("Findings")

	found := false

	for name, p := range ent.Params {

		if p.InjectedOnly() {
			continue
		}
		if p.SuspectIDOR && p.IDLike {
			warn("Possible object-level authorization risk via parameter: " + name + " (needs second user identity to confirm)")
			found = true
		}

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

	validIdentity := hasValidIdentity(ent)
	printed := false

	// ---- Parameter-driven attacks ----
	for name, p := range ent.Params {

		if p.InjectedOnly() {
			continue
		}

		if p.Enumerable {
			info("Enumerate " + name + " sequentially")
			printed = true
		}

		if p.PossibleIDOR {
			info("Attempt cross-user object access via " + name)
			printed = true
		}

		if validIdentity && p.IDLike && p.OwnershipBoundary {
			info("Test horizontal privilege escalation on " + name)
			printed = true
		}

		if validIdentity && p.AuthBoundary && !p.OwnershipBoundary {
			info("Attempt vertical privilege escalation using " + name)
			printed = true
		}

		if p.TokenLike {
			info("Attempt token reuse or swapping on " + name)
			printed = true
		}
	}

	// ---- Authentication phase attacks ----
	if !validIdentity {

		if ent.SeenSignal(knowledge.SigAuthBoundary) {
			info("Test weak credentials")
			info("Username enumeration")
			info("Missing credential handling")
			info("Auth bypass headers (X-Forwarded-For, X-Original-URL)")
			printed = true
		}

	} else {

		// Authenticated attack phase
		if ent.SeenSignal(knowledge.SigAuthBoundary) {
			info("Map privileged endpoints accessible with current session")
			info("Attempt privilege escalation beyond current role")
			printed = true
		}

		if ent.SeenSignal(knowledge.SigObjectOwnership) {
			info("Attempt cross-user object access")
			printed = true
		}
	}

	if !printed {
		info("No high-confidence attack paths identified, manual testing recommended")
	}

	fmt.Println()
}

func reportGraph(ent *knowledge.Entity, k *knowledge.Knowledge) {

	count := 0

	seenAdmin := make(map[string]bool)
	seenUpload := make(map[string]bool)

	// optional: unique endpoints discovered (for better "count")
	seenTo := make(map[string]bool)

	for _, edge := range k.Edges {
		if edge.From != ent.URL {
			continue
		}

		count++

		// unique endpoint count (instead of edge count)
		seenTo[edge.To] = true

		if strings.Contains(edge.To, "admin") {
			if !seenAdmin[edge.To] {
				seenAdmin[edge.To] = true
			}
		}

		if strings.Contains(edge.To, "upload") {
			if !seenUpload[edge.To] {
				seenUpload[edge.To] = true
			}
		}
	}

	// nothing meaningful
	if len(seenTo) == 0 && count == 0 {
		return
	}

	section("Discovered Surface")

	if len(seenTo) > 0 {
		info(fmt.Sprintf("%d related endpoints discovered", len(seenTo)))
	}

	for target := range seenAdmin {
		warn("Administrative surface discovered: " + target)
	}
	for target := range seenUpload {
		warn("Upload endpoint discovered: " + target)
	}

	fmt.Println()
}

func reportJS(ent *knowledge.Entity) {

	if len(ent.Content.JSFindings) == 0 {
		return
	}

	section("JS Intelligence")

	for kind, count := range ent.Content.JSFindings {
		info(fmt.Sprintf("%s: %d", kind, count))
	}

	for _, leak := range ent.Content.JSLeaks {
		warn(fmt.Sprintf("[%s] %s -> %s = %s",
			leak.Kind,
			leak.Source,
			leak.Key,
			leak.Value,
		))
	}

	fmt.Println()
}
