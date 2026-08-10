package derive

import (
	"cwrap/internal/recon/knowledge"
	"sort"
)

func idorFindingParams(ent *knowledge.Entity) []string {
	var primary []string
	var fallback []string

	for name, p := range ent.Params {
		if p == nil {
			continue
		}

		if !(p.PossibleIDOR && p.OwnershipBoundary && p.IDLike) {
			continue
		}

		if isRealInputParam(p) {
			primary = append(primary, name)
			continue
		}

		if isResponseDerivedParam(p) {
			fallback = append(fallback, name)
		}
	}

	sort.Strings(primary)
	sort.Strings(fallback)

	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func suspectIDORFindingParams(ent *knowledge.Entity) []string {
	var primary []string
	var fallback []string

	for name, p := range ent.Params {
		if p == nil {
			continue
		}

		if !(p.SuspectIDOR && p.IDLike) {
			continue
		}

		if isRealInputParam(p) {
			primary = append(primary, name)
			continue
		}

		if isResponseDerivedParam(p) {
			fallback = append(fallback, name)
		}
	}

	sort.Strings(primary)
	sort.Strings(fallback)

	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func isResponseDerivedParam(p *knowledge.ParamIntel) bool {
	if p == nil {
		return false
	}

	return p.Sources[knowledge.ParamJSON] && !isRealInputParam(p)
}
