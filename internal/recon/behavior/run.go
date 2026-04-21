package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/session"
	"cwrap/internal/recon/transport"
)

func (e *Engine) Run(base model.Request, url string) error {
	ent := e.k.Entity(url)

	// ----------------------------------------
	//  Clone base immediately
	// ----------------------------------------
	baseReq := cloneRequest(base)

	// ----------------------------------------
	//  Load persisted session
	// ----------------------------------------
	store, _ := session.Load(base.URL)

	for _, ident := range store.Identities {
		if ident == nil {
			continue
		}
		for _, c := range ident.Cookies {
			if c == nil {
				continue
			}
			ent.SessionCookies[c.Name] = c.Value
			ent.SessionUsed = true
		}
	}

	// populate engine session cookies from persisted store
	for k, v := range ent.SessionCookies {
		e.sessionCookies[k] = v
	}

	// ----------------------------------------
	//  Derive identities FROM baseReq
	// ----------------------------------------
	e.identities = e.deriveIdentities(baseReq)

	if e.debug {
		println("== Active Identities ==")
		for _, id := range e.identities {
			println(" -", id.Name)
		}
	}

	// ----------------------------------------
	//  TRUE BASELINE REQUEST
	// ----------------------------------------
	resp, err := transport.Do(baseReq)
	if err != nil {
		return err
	}

	body, err := transport.ReadBody(resp)
	if err != nil {
		return err
	}

	// ----------------------------------------
	//  Detect stale session and retry
	// ----------------------------------------
	if resp.StatusCode == 401 && ent.SessionUsed {
		if e.debug {
			println("== Stale session detected (401 on live session) — retrying without session cookies ==")
		}
		// clear stale in-memory cookies
		ent.SessionCookies = make(map[string]string)
		e.sessionCookies = make(map[string]string)
		ent.SessionUsed = false

		// rebuild baseReq without the injected cookie header
		baseReq = cloneRequest(base)

		// re-derive identities from the clean request
		e.identities = e.deriveIdentities(baseReq)

		// retry
		resp, err = transport.Do(baseReq)
		if err != nil {
			return err
		}
		body, err = transport.ReadBody(resp)
		if err != nil {
			return err
		}
	}

	// Mark entity as seen
	ent.State.Seen = true
	if meta, ok := e.identityMeta(LiveSession); ok {
		extractIdentity(ent, meta.Name, resp)
		// register session role|uid so it's never added as a live identity
		if id := ent.Identities[LiveSession]; id != nil {
			roleUID := id.Role + "|" + id.UserID
			if roleUID != "|" {
				e.knownRoleUIDs[roleUID] = true
			}
		}
		e.captureSession(ent, meta, resp, base.URL)
	}

	e.baseStatus = resp.StatusCode
	e.baseBody = body
	e.baseFP = makeFingerprint(resp.StatusCode, body)
	ent.AddMethod(baseReq.Method)
	e.int.Learn(baseReq.URL, resp, body)
	e.Expand(ent)

	// ----------------------------------------
	//  Probe loop
	// ----------------------------------------
	for {
		before := ent.ProbeQueue.Len()

		err := e.runQueuedProbes(baseReq, url)
		if err != nil {
			return err
		}

		after := ent.ProbeQueue.Len()
		if after == 0 || after == before {
			break
		}
	}

	return nil
}
