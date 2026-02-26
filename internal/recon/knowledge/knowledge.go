package knowledge

import (
	"fmt"
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
	Params map[string]bool
}

func New(target string) *Knowledge {
	return &Knowledge{
		Target:   target,
		Entities: make(map[string]*Entity),
		Edges:    make([]Edge, 0, 256),
		EdgeSeen: make(map[string]bool),
		Params:   make(map[string]bool),
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
