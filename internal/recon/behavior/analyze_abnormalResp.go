package behavior

import (
	"fmt"

	"cwrap/internal/recon/knowledge"
)

func responseSignificantlyLarger(referenceSize, candidateSize int) bool {
	if candidateSize <= referenceSize {
		return false
	}

	difference := candidateSize - referenceSize

	// Ignore minor template, timestamp, token, and error-message variations.
	if difference < 4*1024 {
		return false
	}

	// A near-empty denial response becoming a substantial response.
	if referenceSize < 512 {
		return candidateSize >= 8*1024
	}

	// For normal-sized responses, require at least three times more data.
	return candidateSize >= referenceSize*3
}

func (e *Engine) analyzeAbnormalResponses(
	target *knowledge.Entity,
	probeFP map[string]string,
	evidence map[string]probeResponseEvidence,
	reference probeReference,
	hasReference bool,
) {
	if target == nil || !hasReference {
		return
	}

	referenceSize := len(reference.Evidence.Body)

	// Follow identity execution order rather than map iteration order.
	for _, id := range e.identities {
		if id.Name == reference.Identity {
			continue
		}

		fp := probeFP[id.Name]
		candidate, ok := evidence[id.Name]

		if !ok || fp == "" {
			continue
		}

		// Identical status+body fingerprint means there is no difference.
		if fp == reference.Fingerprint {
			continue
		}

		if !responseSignificantlyLarger(
			referenceSize,
			len(candidate.Body),
		) {
			continue
		}

		reason := fmt.Sprintf(
			"response body significantly larger than reference identity %s: %d bytes vs %d bytes",
			reference.Identity,
			len(candidate.Body),
			referenceSize,
		)

		recordAbnormalResponse(
			target,
			candidate.URL,
			candidate.Method,
			id.Name,
			candidate.Status,
			candidate.ContentType,
			fp,
			reason,
			candidate.Body,
		)
	}
}
