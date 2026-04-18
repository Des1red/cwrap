package behavior

import "cwrap/internal/recon/knowledge"

type paramEntry struct {
	name    string
	value   string
	baseVal string
}

func storeResponse(
	ent *knowledge.Entity,
	responses map[string]map[string]map[string][]byte,
	statuses map[string]map[string]map[string]int,
	probe knowledge.Probe,
	identity string,
	status int,
	body []byte,
	baseStatus int,
	baseBody []byte,
	baseURL string,
) {
	entries := make([]paramEntry, 0, len(probe.AddQuery)+len(probe.PathParams))

	for k, v := range probe.AddQuery {
		entries = append(entries, paramEntry{k, v, extractCurrentValue(baseURL, k)})
	}
	for k, v := range probe.PathParams {
		entries = append(entries, paramEntry{k, v, probe.PathParamBase[k]})
	}

	for _, e := range entries {
		k, v, baseVal := e.name, e.value, e.baseVal

		if responses[k] == nil {
			responses[k] = map[string]map[string][]byte{}
			statuses[k] = map[string]map[string]int{}
		}
		if responses[k][v] == nil {
			responses[k][v] = map[string][]byte{}
			statuses[k][v] = map[string]int{}
		}

		if baseVal != "" {
			if responses[k][baseVal] == nil {
				responses[k][baseVal] = map[string][]byte{}
				statuses[k][baseVal] = map[string]int{}
			}
			if _, ok := responses[k][baseVal][identity]; !ok {
				responses[k][baseVal][identity] = baseBody
				statuses[k][baseVal][identity] = baseStatus
			}
		}

		responses[k][v][identity] = body
		statuses[k][v][identity] = status

		p := ent.Params[k]
		if p != nil {
			if status == 200 {
				p.IdentityAccess[identity]++
			}
			if status == 401 || status == 403 {
				p.IdentityDenied[identity]++
			}
		}
	}
}
