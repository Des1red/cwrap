package knowledge

import (
	"fmt"
	"time"
)

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

	Identities    map[string]*Identity // name -> identity (for engine logic)
	IdentityIndex map[string]*Identity // fp -> identity (for dedupe/printing)

	SessionCookies map[string]string // name -> value
	SessionUsed    bool              // session reused this run
	SessionIssued  bool              // server issued new cookies
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
			MIMEs:       make(map[string]int),
			Statuses:    make(map[int]int),
			JSFindings:  make(map[string]int),
			JSLeaks:     []JSLeak{},
			SeenJSLeaks: make(map[string]bool),
		},
		Signals: Signals{
			Tags: make(map[Signal]bool),
		},
		Params:         make(map[string]*ParamIntel),
		ProbeQueue:     ProbeQueue{},
		SeenProbes:     make(map[string]bool),
		Identities:     make(map[string]*Identity),
		IdentityIndex:  make(map[string]*Identity),
		SessionCookies: make(map[string]string),
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

	p.Sources[src] = true
}

func (e *Entity) SeenSignal(s Signal) bool {
	return e.Signals.Tags[s]
}

func (e *Entity) AddIdentity(id *Identity) {
	if id == nil {
		return
	}

	// always keep by name for engine comparisons
	e.Identities[id.Name] = id

	// dedupe index for printing / unique mechanism set
	fp := identityFingerprint(id)
	if _, exists := e.IdentityIndex[fp]; !exists {
		e.IdentityIndex[fp] = id
	}
}

func identityFingerprint(id *Identity) string {
	return fmt.Sprintf(
		"%d|%s|%v|%v|%v",
		id.Kind,
		id.AuthScheme,
		id.CookieNames,
		id.HasCSRF,
		id.Rejected,
	)
}
