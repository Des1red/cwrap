package jsintel

import "cwrap/internal/recon/knowledge"

func learnFeatureFlags(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	flags := reFeatureToken.FindAllString(source, -1)
	if len(flags) > 0 {
		ent.Content.JSFindings["feature_token"] += len(flags)
		for i := 0; i < len(flags) && i < 8; i++ {
			appendLeak(ent, "feature_token", sourceURL, "flag", flags[i])
		}
	}

	flagBlocks := reFlagAssign.FindAllString(source, -1)
	if len(flagBlocks) > 0 {
		ent.Content.JSFindings["feature_block"] += len(flagBlocks)
		appendLeak(ent, "feature_block", sourceURL, "flags", "Feature flag object detected")
	}

	enDis := reEnableDisable.FindAllStringSubmatch(source, -1)
	if len(enDis) > 0 {
		ent.Content.JSFindings["feature_toggle"] += len(enDis)
		for i := 0; i < len(enDis) && i < 8; i++ {
			appendLeak(ent, "feature_toggle", sourceURL, enDis[i][1], enDis[i][2])
		}
	}
}
