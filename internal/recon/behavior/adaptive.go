package behavior

import "cwrap/internal/recon/knowledge"

// learnProbeImpact increases Interest for params whose injected values changed behavior.
// probeFP: identityName -> fingerprint(status+bodyhash)
// ref: reference fingerprint (usually no-cred fp for the probe)
func (e *Engine) learnProbeImpact(ent *knowledge.Entity, probe knowledge.Probe, probeFP map[string]string, ref string) {
	if ref == "" || len(probe.AddQuery) == 0 {
		return
	}

	// Did ANY identity differ from the reference for this probe?
	changed := false
	for _, fp := range probeFP {
		if fp != "" && fp != ref {
			changed = true
			break
		}
	}
	if !changed {
		return
	}

	// Attribute change to the params this probe mutated.
	for k := range probe.AddQuery {
		p := ent.Params[k]
		if p == nil || p.InjectedOnly() {
			continue
		}
		p.Interest++
		p.ObservedChanges["input-affects-response"] = true
	}
}
