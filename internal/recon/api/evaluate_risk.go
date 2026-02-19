package api

import "cwrap/internal/recon/knowledge"

func evaluateParamRisk(ent *knowledge.Entity, p *knowledge.ParamIntel) {

	score := 0

	if p.IDLike {
		score += 2
	}

	if ent.SeenSignal(knowledge.SigStateChanging) {
		score += 2
	}

	if p.Enumerable {
		score += 2
	}

	if p.AuthBoundary {
		score += 3
	}

	if p.PossibleIDOR {
		score += 5
	}
	if p.OwnershipBoundary {
		score += 4
	}

	p.RiskScore = score

	switch {
	case score >= 8:
		p.RiskLabel = "HIGH"
	case score >= 5:
		p.RiskLabel = "MEDIUM"
	case score >= 3:
		p.RiskLabel = "LOW"
	default:
		p.RiskLabel = ""
	}
}
