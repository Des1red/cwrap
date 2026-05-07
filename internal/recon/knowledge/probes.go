package knowledge

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

type Probe struct {
	URL    string
	Method string

	AddQuery      map[string]string
	PathParams    map[string]string // path segment param name -> substituted value
	PathParamBase map[string]string // path segment param name -> original value (for base seeding)
	Headers       map[string]string
	Body          []byte
	ContentType   string

	Reason   string
	Priority int

	Created time.Time

	SourceURL string // entity that spawned this probe (for path param accumulation)
}

type ProbeQueue struct {
	items []Probe
}

type ProbeLogEntry struct {
	URL      string
	Method   string
	Reason   string
	Identity string

	Status   int
	FP       string
	Location string

	Count int
}

func (q *ProbeQueue) Len() int {
	return len(q.items)
}

// Push dedupes by Probe.Key() (method|url|reason + sorted query + sorted headers)
// to avoid probe spam while still allowing distinct variations.
func (q *ProbeQueue) push(p Probe) {
	if p.URL == "" || p.Method == "" {
		return
	}
	q.items = append(q.items, p)
}

func (k *Knowledge) PushProbe(target *Entity, p Probe) {
	if p.URL == "" || p.Method == "" {
		return
	}

	root := k.Entity(k.Target)
	key := p.Key()

	if root.SeenProbes[key] {
		return
	}

	if target != root {
		if target.SeenProbes[key] {
			return
		}
		target.SeenProbes[key] = true
	}

	target.ProbeQueue.push(p)
}

func (q *ProbeQueue) PopBest() (Probe, bool) {
	if len(q.items) == 0 {
		return Probe{}, false
	}
	sort.SliceStable(q.items, func(i, j int) bool {
		return q.items[i].Priority > q.items[j].Priority
	})
	p := q.items[0]
	q.items = q.items[1:]
	return p, true
}

func (p Probe) Key() string {

	key := p.Method + "|" + p.URL + "|" + p.Reason

	if len(p.AddQuery) > 0 {
		keys := make([]string, 0, len(p.AddQuery))
		for k := range p.AddQuery {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			key += "|" + k + "=" + p.AddQuery[k]
		}
	}

	if len(p.PathParams) > 0 {
		keys := make([]string, 0, len(p.PathParams))
		for k := range p.PathParams {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key += "|pp:" + k + "=" + p.PathParams[k]
		}
	}

	if len(p.Headers) > 0 {
		keys := make([]string, 0, len(p.Headers))
		for k := range p.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			key += "|h:" + k + "=" + p.Headers[k]
		}
	}

	if len(p.Body) > 0 {
		sum := sha256.Sum256(p.Body)
		key += "|body:" + fmt.Sprintf("%x", sum[:8]) // first 8 bytes is enough for dedupe
	}
	return key
}

func (e *Entity) AddProbeLog(p ProbeLogEntry) {
	if p.URL == "" || p.Method == "" || p.Identity == "" {
		return
	}

	if p.Count == 0 {
		p.Count = 1
	}

	for i := range e.ProbeLog {
		old := &e.ProbeLog[i]

		if old.URL == p.URL &&
			old.Method == p.Method &&
			old.Reason == p.Reason &&
			old.Identity == p.Identity &&
			old.Status == p.Status &&
			old.Location == p.Location &&
			old.FP == p.FP {
			old.Count += p.Count
			return
		}
	}

	e.ProbeLog = append(e.ProbeLog, p)
}
