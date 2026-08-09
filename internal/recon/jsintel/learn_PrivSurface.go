package jsintel

import (
	"cwrap/internal/recon/jsintel/common"
	"cwrap/internal/recon/knowledge"
)

func learnPrivilegeSurfaces(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	roleHits := common.ReRoleCompare.FindAllStringSubmatch(source, -1)
	if len(roleHits) > 0 {
		ent.Content.JSFindings[knowledge.JSFindingRoleCheck] += len(roleHits)
		for i := 0; i < len(roleHits) && i < 5; i++ {
			common.AppendLeak(ent, knowledge.JSFindingRoleCheck, sourceURL, "role", roleHits[i][2])
		}
	}

	adminBool := common.ReAdminBool.FindAllStringSubmatch(source, -1)
	if len(adminBool) > 0 {
		ent.Content.JSFindings[knowledge.JSFindingPrivFlag] += len(adminBool)
		for i := 0; i < len(adminBool) && i < 5; i++ {
			common.AppendLeak(ent, knowledge.JSFindingPrivFlag, sourceURL, adminBool[i][1], adminBool[i][2])
		}
	}

	if common.RePrivGate.FindStringIndex(source) != nil {
		ent.Content.JSFindings[knowledge.JSFindingPrivGate]++
		common.AppendLeak(ent, knowledge.JSFindingPrivGate, sourceURL, "if_gate", "Privilege gate conditional detected")
	}
}
