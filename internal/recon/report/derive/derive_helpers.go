package derive

import "cwrap/internal/recon/knowledge"

func isRealInputParam(p *knowledge.ParamIntel) bool {
	if p == nil {
		return false
	}

	return p.Sources[knowledge.ParamQuery] ||
		p.Sources[knowledge.ParamPath] ||
		p.Sources[knowledge.ParamForm]
}
