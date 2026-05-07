package behavior

import "cwrap/internal/recon/knowledge"

func (e *Engine) analyzeMethods(ent *knowledge.Entity) {

	if len(ent.HTTP.Methods) == 0 {
		return
	}

	methods := ent.HTTP.Methods

	// ---------------------------------
	// STATE CHANGING ENDPOINT
	// ---------------------------------
	if methods["POST"] ||
		methods["PUT"] ||
		methods["PATCH"] ||
		methods["DELETE"] {

		ent.Tag(knowledge.SigStateChanging)
	}

	// ---------------------------------
	// JSON API SURFACE
	// ---------------------------------
	if ent.Content.LooksLikeJSON &&
		(methods["POST"] ||
			methods["PUT"] ||
			methods["PATCH"]) {

		ent.Tag(knowledge.SigHasJSONBody)
	}
}
