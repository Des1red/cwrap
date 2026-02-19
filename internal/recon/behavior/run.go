package behavior

import "cwrap/internal/model"

// Run executes the full probing lifecycle.
func (e *Engine) Run(base model.Request, url string, baseStatus int, baseBody []byte) error {

	ent := e.k.Entity(url)

	// initial strategy seed
	e.Expand(ent)

	// probing loop: continues while new probes are generated
	for {
		before := ent.ProbeQueue.Len()

		err := e.runQueuedProbes(base, url, baseStatus, baseBody)
		if err != nil {
			return err
		}

		after := ent.ProbeQueue.Len()

		// no new knowledge → stop
		if after == 0 || after == before {
			break
		}
	}

	return nil
}
