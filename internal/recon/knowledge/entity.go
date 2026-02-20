package knowledge

import "time"

// Entity is the ONLY primary object: intelligence about a URL.
type Entity struct {
	URL string

	State EntityState

	HTTP HTTPIntel

	Content ContentIntel

	Signals Signals

	// Discovered params (query/form/json keys). This is per-URL.
	Params map[string]*ParamIntel

	// For active probing: queue of candidate probes for this URL.
	ProbeQueue ProbeQueue
	SeenProbes map[string]bool
}

func (e *Entity) Tag(s Signal) {
	if !e.Signals.Tags[s] {
		e.Signals.Tags[s] = true
	}
}

func NewEntity(url string) *Entity {
	return &Entity{
		URL: url,
		State: EntityState{
			Seen:       false,
			Scanned:    false,
			FirstSeen:  time.Time{},
			LastSeen:   time.Time{},
			LastProbe:  time.Time{},
			ProbeCount: 0,
		},
		HTTP: HTTPIntel{
			Methods: make(map[string]bool),
			Headers: make(map[string]bool),
		},
		Content: ContentIntel{
			MIMEs:    make(map[string]int),
			Statuses: make(map[int]int),
		},
		Signals: Signals{
			Tags: make(map[Signal]bool),
		},
		Params:     make(map[string]*ParamIntel),
		ProbeQueue: ProbeQueue{},
		SeenProbes: make(map[string]bool),
	}
}

func (e *Entity) MarkSeen(now time.Time) {
	if !e.State.Seen {
		e.State.Seen = true
		e.State.FirstSeen = now
	}
	e.State.LastSeen = now
}

func (e *Entity) MarkScanned(now time.Time) {
	e.State.Scanned = true
	e.State.LastProbe = now
	e.State.ProbeCount++
}

func (e *Entity) AddMethod(m string) {
	if m == "" {
		return
	}
	e.HTTP.Methods[m] = true
}

func (e *Entity) AddHeader(name string) {
	if name == "" {
		return
	}
	e.HTTP.Headers[name] = true
}

func (e *Entity) AddParam(name string, src ParamSource) {
	if name == "" {
		return
	}

	p, ok := e.Params[name]
	if !ok {
		p = &ParamIntel{
			Name:            name,
			Sources:         map[ParamSource]bool{},
			ObservedChanges: map[string]bool{},
			IdentityAccess:  map[string]int{},
			IdentityDenied:  map[string]int{},
		}
		e.Params[name] = p
	}

	if !p.Sources[src] {
		p.Sources[src] = true
	}
}

func (e *Entity) SeenSignal(s Signal) bool {
	return e.Signals.Tags[s]
}
