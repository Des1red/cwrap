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
	kg *knowledge.Knowledge,
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

		_, isPathParam := probe.PathParams[k]
		if baseVal != "" && !isPathParam {
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

		// path params accumulate on source entity (the one that ran expandPathIDs)
		// query params accumulate on the target entity
		accumEnt := ent
		if isPathParam && probe.SourceURL != "" {
			accumEnt = kg.Entity(probe.SourceURL)
		}
		if accumEnt.AccumResponses[k] == nil {
			accumEnt.AccumResponses[k] = map[string]map[string][]byte{}
			accumEnt.AccumStatuses[k] = map[string]map[string]int{}
		}
		if accumEnt.AccumResponses[k][v] == nil {
			accumEnt.AccumResponses[k][v] = map[string][]byte{}
			accumEnt.AccumStatuses[k][v] = map[string]int{}
		}
		accumEnt.AccumResponses[k][v][identity] = body
		accumEnt.AccumStatuses[k][v][identity] = status

		p := accumEnt.Params[k]
		if p != nil && shouldReportIdentity(identity) {
			if status == 200 {
				p.IdentityAccess[identity]++
			}
			if status == 401 || status == 403 {
				p.IdentityDenied[identity]++
			}
		}
	}
}

func shouldReportIdentity(name string) bool {
	return name != LiveSession
}
