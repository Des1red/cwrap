package entity

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type entityGroup struct {
	Key      string
	URLs     []string
	Entities []*knowledge.Entity
}

func entityGroupKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, p := range parts {
		if looksNumeric(p) {
			parts[i] = "{id}"
		}
	}

	path := "/" + strings.Join(parts, "/")
	if path == "/" {
		path = u.Scheme + "://" + u.Host
	} else {
		path = u.Scheme + "://" + u.Host + path
	}

	q := u.Query()
	if len(q) == 0 {
		return path
	}

	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	queryParts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := q.Get(k)
		if looksNumeric(v) {
			v = "{id}"
		}
		queryParts = append(queryParts, k+"="+v)
	}

	return path + "?" + strings.Join(queryParts, "&")
}

func looksNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// isUnconfirmedAdminSurface reports whether an entity carries the
// AdminSurface path-pattern signal but has no confirmed HTTP evidence
// behind it — either because every probe against it returned the same
// SPA-fallback shell as the scan's base page, or because every probe
// failed outright (no Methods, no Statuses recorded at all). In both
// cases the only thing known about this entity is its URL, not its
// actual behavior.
func isUnconfirmedAdminSurface(ent *knowledge.Entity) bool {
	if ent == nil || !ent.SeenSignal(knowledge.SigAdminSurface) {
		return false
	}

	if ent.State.IsSPAFallback {
		return true
	}

	fullyUnreachable := ent.State.ProbeCount > 0 &&
		len(ent.HTTP.Methods) == 0 &&
		len(ent.Content.Statuses) == 0

	return fullyUnreachable
}

func entityGroupsByRoute(k *knowledge.Knowledge) []entityGroup {
	byKey := map[string]*entityGroup{}

	for _, u := range entityURLsByRoute(k) {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		// Unconfirmed-AdminSurface entities move to their own section
		// (see entityGroupsUnconfirmedAdminSurface) instead of appearing
		// here alongside entities with real, confirmed behavior.
		if isUnconfirmedAdminSurface(ent) {
			continue
		}

		// Any other SPA-fallback entity (no AdminSurface signal) has
		// nothing worth reporting — same shell as every other unmatched
		// route, dropped entirely, unchanged from prior behavior.
		if ent.State.IsSPAFallback {
			continue
		}

		key := entityGroupKey(u)

		g := byKey[key]
		if g == nil {
			g = &entityGroup{Key: key}
			byKey[key] = g
		}

		g.URLs = append(g.URLs, u)
		g.Entities = append(g.Entities, ent)
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]entityGroup, 0, len(keys))
	for _, key := range keys {
		g := byKey[key]

		sort.Slice(g.Entities, func(i, j int) bool {
			return g.Entities[i].URL < g.Entities[j].URL
		})
		sort.Strings(g.URLs)

		out = append(out, *g)
	}

	return out
}

// entityGroupsUnconfirmedAdminSurface returns route groups for entities
// flagged by isUnconfirmedAdminSurface: the AdminSurface signal is
// present (a URL-pattern match made before any request was sent), but
// no real response evidence backs it up — either an SPA-shell match or
// total unreachability. Surfaced separately from entityGroupsByRoute so
// unconfirmed leads never sit alongside confirmed endpoint behavior.
func entityGroupsUnconfirmedAdminSurface(k *knowledge.Knowledge) []entityGroup {
	byKey := map[string]*entityGroup{}

	for _, u := range entityURLsByRoute(k) {
		ent := k.Entities[u]
		if !isUnconfirmedAdminSurface(ent) {
			continue
		}

		key := entityGroupKey(u)

		g := byKey[key]
		if g == nil {
			g = &entityGroup{Key: key}
			byKey[key] = g
		}

		g.URLs = append(g.URLs, u)
		g.Entities = append(g.Entities, ent)
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]entityGroup, 0, len(keys))
	for _, key := range keys {
		g := byKey[key]

		sort.Slice(g.Entities, func(i, j int) bool {
			return g.Entities[i].URL < g.Entities[j].URL
		})
		sort.Strings(g.URLs)

		out = append(out, *g)
	}

	return out
}
