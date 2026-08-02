package jsintel

import "cwrap/internal/recon/knowledge"

func learnPrivilegeSurfaces(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	roleHits := reRoleCompare.FindAllStringSubmatch(source, -1)
	if len(roleHits) > 0 {
		ent.Content.JSFindings["role_check"] += len(roleHits)
		for i := 0; i < len(roleHits) && i < 5; i++ {
			appendLeak(ent, "role_check", sourceURL, "role", roleHits[i][2])
		}
	}

	adminBool := reAdminBool.FindAllStringSubmatch(source, -1)
	if len(adminBool) > 0 {
		ent.Content.JSFindings["priv_flag"] += len(adminBool)
		for i := 0; i < len(adminBool) && i < 5; i++ {
			appendLeak(ent, "priv_flag", sourceURL, adminBool[i][1], adminBool[i][2])
		}
	}

	if rePrivGate.FindStringIndex(source) != nil {
		ent.Content.JSFindings["priv_gate"]++
		appendLeak(ent, "priv_gate", sourceURL, "if_gate", "Privilege gate conditional detected")
	}
}
