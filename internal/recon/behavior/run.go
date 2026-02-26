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

	// ----------------------------------------
	//  Inject cookies into baseReq
	// ----------------------------------------
	if ck := cookieHeader(ent.SessionCookies); ck != "" {
		baseReq.Flags.Headers = upsertHeader(baseReq.Flags.Headers, "Cookie", ck)
	}

	// ----------------------------------------
	//  Derive identities FROM baseReq
	// ----------------------------------------
	e.identities = deriveIdentities(baseReq)

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

	if meta, ok := e.identityMeta("baseline"); ok {
		extractIdentity(ent, meta.Name, resp)
		e.captureSession(ent, meta, resp, base.URL)
	}

	e.baseStatus = resp.StatusCode
	e.baseBody = body
	e.baseFP = makeFingerprint(resp.StatusCode, body)

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
