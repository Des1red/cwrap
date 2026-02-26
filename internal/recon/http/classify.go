package http

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/paramintel"
)

func (i interpreter) ClassifyParam(ent *knowledge.Entity, name string) {

	p, ok := ent.Params[name]
	if !ok {
		return
	}

	paramintel.ClassifyParam(ent, p)
}
