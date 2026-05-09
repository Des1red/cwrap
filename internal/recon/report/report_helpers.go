package report

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// paramHasEvidence returns true if a param has any non-default evidence worth reporting.
func paramHasEvidence(p *knowledge.ParamIntel) bool {
	if p.LikelyReflection || p.LikelyObjectAccess || p.Enumerable {
		return true
	}
	if p.AuthBoundary || p.OwnershipBoundary || p.PossibleIDOR || p.SuspectIDOR {
		return true
	}
	if p.Interest > 0 {
		return true
	}
	if len(p.ObservedChanges) > 0 {
		return true
	}
	// injected params with only access/denied maps don't have real evidence —
	// those maps just reflect entity-level auth, not param-specific behavior
	if p.InjectedOnly() {
		return false
	}
	// access is only meaningful if there's also denial — mixed access = auth boundary evidence
	if len(p.IdentityAccess) > 0 && len(p.IdentityDenied) > 0 {
		return true
	}
	// denial alone is always meaningful
	if len(p.IdentityDenied) > 0 {
		return true
	}
	return false
}

// hasNonInjectedParams returns true if entity has any params from real sources.
func hasNonInjectedParams(ent *knowledge.Entity) bool {
	for _, p := range ent.Params {
		if p == nil {
			continue
		}
		if !p.InjectedOnly() {
			return true
		}
	}
	return false
}

func paramSourceShort(p *knowledge.ParamIntel) string {
	if p.Sources[knowledge.ParamQuery] {
		return "query"
	}
	if p.Sources[knowledge.ParamForm] {
		return "form"
	}
	if p.Sources[knowledge.ParamJSON] {
		return "json"
	}
	if p.Sources[knowledge.ParamPath] {
		return "path"
	}
	return "injected"
}

func paramSourceLabel(p *knowledge.ParamIntel, src knowledge.ParamSource) string {
	switch src {
	case knowledge.ParamInjected:
		if p.DiscoveryReason != "" {
			return "injected (scanner discovery: " + p.DiscoveryReason + ")"
		}
		return "injected (scanner discovery)"
	case knowledge.ParamQuery:
		return "query"
	case knowledge.ParamForm:
		return "form"
	case knowledge.ParamJSON:
		return "json"
	case knowledge.ParamPath:
		return "path"
	default:
		return "unknown"
	}
}

func copySet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func identityKindLabel(k knowledge.IdentityKind) string {
	switch k {
	case knowledge.IdentityUnknown:
		return "IdentityUnknown"
	case knowledge.IdentityNone:
		return "IdentityNone"
	case knowledge.IdentityBootstrap:
		return "IdentityBootstrap"
	case knowledge.IdentityUser:
		return "IdentityUser"
	case knowledge.IdentityElevated:
		return "IdentityElevated"
	case knowledge.IdentityInvalid:
		return "IdentityInvalid"
	default:
		return "IdentityKind(?)"
	}
}

func isRealInputParam(p *knowledge.ParamIntel) bool {
	if p == nil {
		return false
	}

	return p.Sources[knowledge.ParamQuery] ||
		p.Sources[knowledge.ParamPath] ||
		p.Sources[knowledge.ParamForm]
}

func sortedEntityURLs(k *knowledge.Knowledge) []string {
	urls := make([]string, 0, len(k.Entities))
	for u := range k.Entities {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func probeIdentityKindLabel(k knowledge.ProbeIdentityKind) string {
	switch k {
	case knowledge.ProbeIdentitySynthetic:
		return "synthetic"
	case knowledge.ProbeIdentityLive:
		return "live"
	default:
		return ""
	}
}

func activeSignals(ent *knowledge.Entity) []string {
	if ent == nil || len(ent.Signals.Tags) == 0 {
		return nil
	}
	var out []string
	for s, on := range ent.Signals.Tags {
		if on {
			out = append(out, s.String())
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, on := range m {
		if on {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func signalCount(ent *knowledge.Entity) int {
	if ent == nil {
		return 0
	}
	n := 0
	for _, on := range ent.Signals.Tags {
		if on {
			n++
		}
	}
	return n
}

func entityURLsByRoute(k *knowledge.Knowledge) []string {
	urls := make([]string, 0, len(k.Entities))
	for u := range k.Entities {
		urls = append(urls, u)
	}

	sort.Slice(urls, func(i, j int) bool {
		ai := routeSortKey(urls[i])
		aj := routeSortKey(urls[j])

		if ai.family != aj.family {
			return ai.family < aj.family
		}

		if ai.depth != aj.depth {
			return ai.depth < aj.depth
		}

		if ai.numeric && aj.numeric && ai.num != aj.num {
			return ai.num < aj.num
		}

		if ai.numeric != aj.numeric {
			return !ai.numeric
		}

		return urls[i] < urls[j]
	})

	return urls
}

func routeSortKey(raw string) routeKey {
	u, err := url.Parse(raw)
	if err != nil {
		return routeKey{family: raw}
	}

	path := strings.Trim(u.Path, "/")
	if path == "" {
		return routeKey{family: "/", depth: 0}
	}

	parts := strings.Split(path, "/")
	depth := len(parts)

	last := parts[len(parts)-1]
	if n, err := strconv.Atoi(last); err == nil {
		family := "/" + strings.Join(parts[:len(parts)-1], "/")
		return routeKey{
			family:  family,
			depth:   depth,
			numeric: true,
			num:     n,
		}
	}

	return routeKey{
		family: "/" + path,
		depth:  depth,
	}
}
