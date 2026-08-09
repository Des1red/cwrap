package jsintel

import (
	"cwrap/internal/recon/jsintel/common"
	"cwrap/internal/recon/knowledge"
)

func learnFeatureFlags(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	flags := common.ReFeatureToken.FindAllString(source, -1)
	if len(flags) > 0 {
		ent.Content.JSFindings[knowledge.JSFindingFeatureToken] += len(flags)
		for i := 0; i < len(flags) && i < 8; i++ {
			common.AppendLeak(ent, knowledge.JSFindingFeatureToken, sourceURL, "flag", flags[i])
		}
	}

	flagBlocks := common.ReFlagAssign.FindAllString(source, -1)
	if len(flagBlocks) > 0 {
		ent.Content.JSFindings[knowledge.JSFindingFeatureBlock] += len(flagBlocks)
		common.AppendLeak(ent, knowledge.JSFindingFeatureBlock, sourceURL, "flags", "Feature flag object detected")
	}

	enDis := common.ReEnableDisable.FindAllStringSubmatch(source, -1)
	if len(enDis) > 0 {
		ent.Content.JSFindings[knowledge.JSFindingFeatureToggle] += len(enDis)
		for i := 0; i < len(enDis) && i < 8; i++ {
			common.AppendLeak(ent, knowledge.JSFindingFeatureToggle, sourceURL, enDis[i][1], enDis[i][2])
		}
	}
}
