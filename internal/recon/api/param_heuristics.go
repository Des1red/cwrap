package api

import (
	"cwrap/internal/recon/knowledge"
	"strings"
)

func classifyParam(ent *knowledge.Entity, p *knowledge.ParamIntel) {

	name := strings.ToLower(p.Name)

	// ---- ID-like ----
	if name == "id" ||
		strings.HasSuffix(name, "id") ||
		strings.Contains(name, "user") ||
		strings.Contains(name, "account") {

		p.IDLike = true
		ent.Tag(knowledge.SigIDLikeParam)
	}

	// ---- token-like ----
	if strings.Contains(name, "token") ||
		strings.Contains(name, "session") ||
		strings.Contains(name, "auth") ||
		strings.Contains(name, "key") {

		p.TokenLike = true
		ent.Tag(knowledge.SigTokenLike)
	}

	// ---- debug flags ----
	if strings.Contains(name, "debug") ||
		strings.Contains(name, "test") ||
		strings.Contains(name, "dev") ||
		strings.Contains(name, "preview") {

		p.DebugLike = true
		ent.Tag(knowledge.SigDebugFlag)
	}
}
