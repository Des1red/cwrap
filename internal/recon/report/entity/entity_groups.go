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

func entityGroupsByRoute(k *knowledge.Knowledge) []entityGroup {
	byKey := map[string]*entityGroup{}

	for _, u := range entityURLsByRoute(k) {
		ent := k.Entities[u]
		if ent == nil || ent.State.IsSPAFallback {
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
