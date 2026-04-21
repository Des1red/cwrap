package api

import (
	"cwrap/internal/recon/jsonintel"
	"cwrap/internal/recon/knowledge"
)

func (e *Engine) extractJSON(ent *knowledge.Entity, data []byte) {
	jsonintel.ExtractParams(ent, e.k, data)
}
