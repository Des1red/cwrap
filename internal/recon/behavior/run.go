package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/transport"
)

// Run executes the full probing lifecycle.
func (e *Engine) Run(base model.Request, url string) error {

	ent := e.k.Entity(url)
	e.identities = deriveIdentities(base)

	// ---- TRUE BASELINE REQUEST ----
	resp, err := transport.Do(base)
	if err != nil {
		return err
	}

	body, err := transport.ReadBody(resp)
	if err != nil {
		return err
	}

	// store global baseline (used everywhere)
	e.baseStatus = resp.StatusCode
	e.baseBody = body
	e.baseFP = makeFingerprint(resp.StatusCode, body)

	// let interpreter learn from baseline
	e.int.Learn(base.URL, resp, body)

	// ---- initial strategy seed ----
	e.Expand(ent)

	// ---- probing loop ----
	for {
		before := ent.ProbeQueue.Len()

		err := e.runQueuedProbes(base, url)
		if err != nil {
			return err
		}

		after := ent.ProbeQueue.Len()

		// stop when no new probes generated
		if after == 0 || after == before {
			break
		}
	}

	return nil
}
