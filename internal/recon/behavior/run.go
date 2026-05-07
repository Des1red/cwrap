package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/session"
	"cwrap/internal/recon/transport"
	"net/http"
	"time"
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
			e.sessionCookies[c.Name] = c.Value
			ent.SessionUsed = true
		}
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
	//  Public BASELINE REQUEST
	// ----------------------------------------
	// Sessionless baseline used for SPA/catchall fingerprint.
	resp, err := transport.Do(baseReq)
	if err != nil {
		return err
	}

	body, err := transport.ReadBody(resp)
	if err != nil {
		return err
	}

	// ----------------------------------------
	//
	//	Detect stale persisted session
	//
	// ----------------------------------------
	var sessionResp *http.Response
	// Separate check: apply LiveSession once only to verify stored cookies.
	if ent.SessionUsed {
		if meta, ok := e.identityMeta(knowledge.LiveSession); ok {
			sessionReq := meta.Apply(cloneRequest(baseReq))

			sessionResp, err = transport.Do(sessionReq)
			if err != nil {
				return err
			}

			_, err = transport.ReadBody(sessionResp)
			if err != nil {
				return err
			}

			if sessionResp.StatusCode == 401 {
				if e.debug {
					println("== Stale session detected — continuing without stored session cookies ==")
				}

				ent.SessionCookies = make(map[string]string)
				e.sessionCookies = make(map[string]string)
				ent.SessionUsed = false
				sessionResp = nil

				e.identities = e.deriveIdentities(baseReq)
			}
		}
	}
	// Mark entity as seen
	ent.State.Seen = true
	e.registerURLQueryParams(ent)
	if sessionResp != nil && ent.SessionUsed {
		if meta, ok := e.identityMeta(knowledge.LiveSession); ok {
			extractIdentity(ent, meta.Name, sessionResp)
			// register session role|uid so it's never added as a live identity
			if id := ent.Identities[knowledge.LiveSession]; id != nil {
				roleUID := id.Role + "|" + id.UserID
				if roleUID != "|" {
					e.knownRoleUIDs[roleUID] = true
				}
			}
			e.captureSession(ent, meta, sessionResp, base.URL)
		}
	}

	e.baseStatus = resp.StatusCode
	e.baseBody = body
	e.baseFP = fpString(resp.StatusCode, body)
	ent.AddMethod(baseReq.Method)
	e.int.Learn(baseReq.URL, resp, body)
	e.Expand(ent)

	// push additional seed URLs from grouped --tfile recon
	// each seed gets probed as if discovered organically
	for _, seedURL := range base.Flags.SeedURLs {
		if seedURL == url {
			continue // root already handled
		}
		e.k.PushProbe(ent, knowledge.Probe{
			URL:      seedURL,
			Method:   "GET",
			Reason:   knowledge.ReasonLinkProbe,
			Priority: 200,
			Created:  time.Now(),
		})
	}
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
	// ----------------------------------------
	//  Form requeue — POST form entities
	//  with real bodies after discovery settles
	// ----------------------------------------
	e.requeueForms(baseReq, url)
	if err := e.runQueuedProbes(baseReq, url); err != nil {
		return err
	}
	// strip auth signals from SPA shell entities before returning
	e.stripSPAShellSignals()

	return nil
}
