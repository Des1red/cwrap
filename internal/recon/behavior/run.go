package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/session"
	"cwrap/internal/recon/transport"
)

// Run executes the full probing lifecycle.
func (e *Engine) Run(base model.Request, url string) error {
	ent := e.k.Entity(url)
	e.identities = deriveIdentities(base)

	if e.debug {
		println("== Active Identities ==")
		for _, id := range e.identities {
			println(" -", id.Name)
		}
	}

	// ---- LOAD SESSION ----
	store, _ := session.Load(base.URL)
	for _, c := range store.Cookies {
		ent.SessionCookies[c.Name] = c.Value
		ent.SessionUsed = true
	}

	// IMPORTANT: don't mutate the caller's base
	baseReq := cloneRequest(base)

	// Inject cookies once, as a single Cookie header
	if ck := cookieHeader(ent.SessionCookies); ck != "" {
		baseReq.Flags.Headers = upsertHeader(baseReq.Flags.Headers, "Cookie", ck)
	}

	// ---- TRUE BASELINE REQUEST ----
	resp, err := transport.Do(baseReq)
	if err != nil {
		return err
	}

	body, err := transport.ReadBody(resp)
	if err != nil {
		return err
	}

	captureSession(ent, resp, base.URL)

	e.baseStatus = resp.StatusCode
	e.baseBody = body
	e.baseFP = makeFingerprint(resp.StatusCode, body)

	e.int.Learn(baseReq.URL, resp, body)

	e.Expand(ent)

	for {
		before := ent.ProbeQueue.Len()

		err := e.runQueuedProbes(baseReq, url) // pass the cookie-injected baseReq
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
