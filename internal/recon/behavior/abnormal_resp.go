package behavior

import (
	"cwrap/internal/recon/knowledge"
)

type probeResponseEvidence struct {
	URL         string
	Method      string
	Body        []byte
	ContentType string
	Status      int
}

type probeReference struct {
	Identity    string
	Fingerprint string
	Evidence    probeResponseEvidence
}

func recordAbnormalResponse(
	ent *knowledge.Entity,
	targetURL string,
	method string,
	identity string,
	status int,
	contentType string,
	fingerprint string,
	reason string,
	body []byte,
) bool {
	if ent == nil {
		return false
	}

	return ent.AddAbnormalResponse(knowledge.AbnormalResponse{
		URL:         targetURL,
		Method:      method,
		Identity:    identity,
		Status:      status,
		ContentType: contentType,
		BodySize:    len(body),
		Fingerprint: fingerprint,
		Reason:      reason,
		Body:        append([]byte(nil), body...),
	})
}
