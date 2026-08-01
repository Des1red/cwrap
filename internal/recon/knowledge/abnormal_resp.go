package knowledge

import "fmt"

type AbnormalResponse struct {
	URL         string
	Method      string
	Identity    string
	Status      int
	ContentType string
	BodySize    int
	Fingerprint string
	Reason      string
	Body        []byte
}

func (e *Entity) AddAbnormalResponse(response AbnormalResponse) bool {
	if response.URL == "" ||
		response.Method == "" ||
		response.Identity == "" ||
		response.Fingerprint == "" {
		return false
	}

	if e.SeenAbnormalResponses == nil {
		e.SeenAbnormalResponses = make(map[string]bool)
	}

	key := fmt.Sprintf(
		"%s|%s|%d|%s",
		response.Method,
		response.URL,
		response.Status,
		response.Fingerprint,
	)

	if e.SeenAbnormalResponses[key] {
		return false
	}

	e.SeenAbnormalResponses[key] = true
	e.AbnormalResponses = append(e.AbnormalResponses, response)

	return true
}
