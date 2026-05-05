package knowledge

import (
	"fmt"
	"strings"
	"sync"
)

type Knowledge struct {
	Target string

	mu sync.RWMutex

	// One canonical record per URL.
	Entities map[string]*Entity

	// Relationships between entities (how we discovered / why we care).
	Edges    []Edge
	EdgeSeen map[string]bool
	// Global parameter dictionary (useful for cross-target heuristics).
	Params               map[string]bool
	DiscoveredIdentities map[string]map[string]string
	KnownJSSuffixes      sync.Map
	StaticAssets         map[string]bool
	Emails               map[string]bool
	Phones               map[string]bool
}

func New(target string) *Knowledge {
	return &Knowledge{
		Target:               target,
		Entities:             make(map[string]*Entity),
		Edges:                make([]Edge, 0, 256),
		EdgeSeen:             make(map[string]bool),
		Params:               make(map[string]bool),
		DiscoveredIdentities: make(map[string]map[string]string),
		StaticAssets:         make(map[string]bool),
		Emails:               make(map[string]bool),
		Phones:               make(map[string]bool),
	}
}

// Entity returns the canonical mutable intelligence object for this URL.
func (k *Knowledge) Entity(url string) *Entity {
	k.mu.Lock()
	defer k.mu.Unlock()

	if e, ok := k.Entities[url]; ok {
		return e
	}
	e := NewEntity(url)
	k.Entities[url] = e
	return e
}

func (k *Knowledge) AddEdge(from, to string, t EdgeType) {
	if from == "" || to == "" {
		return
	}

	key := fmt.Sprintf("%s|%s|%d", from, to, t)

	k.mu.Lock()
	if k.EdgeSeen[key] {
		k.mu.Unlock()
		return
	}
	k.EdgeSeen[key] = true
	k.Edges = append(k.Edges, Edge{From: from, To: to, Type: t})
	// mark destination as organically discovered for HTML/form edges
	// this prevents path-variant probes from wrongly suppressing method sweeps
	if t == EdgeDiscoveredFromHTML || t == EdgeFormAction {
		dest := k.Entities[to]
		if dest == nil {
			dest = NewEntity(to)
			k.Entities[to] = dest
		}
		dest.State.OrganicallyDiscovered = true
		// if it was previously marked as a path variant, clear it
		dest.State.IsPathVariant = false
	}
	k.mu.Unlock()
}
func (k *Knowledge) AddParam(name string) {
	if name == "" {
		return
	}
	k.mu.Lock()
	k.Params[name] = true
	k.mu.Unlock()
}

func (p *ParamIntel) InjectedOnly() bool {
	if len(p.Sources) == 1 && p.Sources[ParamInjected] {
		return true
	}
	return false
}

func (k *Knowledge) RegisterJSSuffix(suffix string) bool {
	_, loaded := k.KnownJSSuffixes.LoadOrStore(suffix, struct{}{})
	return !loaded // true = first registration, false = already existed
}

func (k *Knowledge) HasJSSuffix(suffix string) bool {
	_, ok := k.KnownJSSuffixes.Load(suffix)
	return ok
}

func (k *Knowledge) AddStaticAsset(url string) {
	if url == "" {
		return
	}
	url = stripQuery(url)
	k.mu.Lock()
	k.StaticAssets[url] = true
	k.mu.Unlock()
}

func stripQuery(raw string) string {
	if i := strings.IndexByte(raw, '?'); i != -1 {
		return raw[:i]
	}
	return raw
}

func (k *Knowledge) AddEmail(v string) {
	if v == "" {
		return
	}
	k.mu.Lock()
	k.Emails[strings.ToLower(strings.TrimSpace(v))] = true
	k.mu.Unlock()
}

func (k *Knowledge) AddPhone(v string) {
	if v == "" {
		return
	}
	k.mu.Lock()
	k.Phones[strings.TrimSpace(v)] = true
	k.mu.Unlock()
}
