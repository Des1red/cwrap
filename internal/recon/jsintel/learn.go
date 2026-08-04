package jsintel

import "cwrap/internal/recon/knowledge"

func Learn(k *knowledge.Knowledge, ent *knowledge.Entity, sourceURL string, body []byte) []JSEndpoint {
	if ent == nil {
		return nil
	}
	if ent.Content.JSFindings == nil {
		ent.Content.JSFindings = make(map[string]int)
	}

	source := string(body)

	// ----------------------------
	// Secrets / keys
	// ----------------------------
	learnSecrets(k, ent, sourceURL, source)

	// ----------------------------
	// Endpoint discovery
	// ----------------------------
	endpoints := discoverEndpoints(
		ent,
		sourceURL,
		source,
	)
	// ----------------------------
	// Roles / privilege surfaces
	// ----------------------------
	learnPrivilegeSurfaces(ent, sourceURL, source)

	// ----------------------------
	// Feature flags
	// ----------------------------
	learnFeatureFlags(ent, sourceURL, source)

	// ----------------------------
	// Env vars
	// ----------------------------
	learnEnvironmentReferences(ent, sourceURL, source)

	// ----------------------------
	// Hardcoded hosts / internal infra
	// ----------------------------
	learnInfrastructure(ent, sourceURL, source)

	return endpoints
}
