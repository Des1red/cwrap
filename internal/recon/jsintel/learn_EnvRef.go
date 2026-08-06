package jsintel

import (
	"cwrap/internal/recon/jsintel/common"
	"cwrap/internal/recon/knowledge"
)

func learnEnvironmentReferences(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	procEnv := common.ReProcEnv.FindAllStringSubmatch(source, -1)
	if len(procEnv) > 0 {
		ent.Content.JSFindings["env_ref"] += len(procEnv)
		for i := 0; i < len(procEnv) && i < 10; i++ {
			common.AppendLeak(ent, "env_ref", sourceURL, "process.env", procEnv[i][1])
		}
	}

	metaEnv := common.ReImportMetaEnv.FindAllStringSubmatch(source, -1)
	if len(metaEnv) > 0 {
		ent.Content.JSFindings["env_ref"] += len(metaEnv)
		for i := 0; i < len(metaEnv) && i < 10; i++ {
			common.AppendLeak(ent, "env_ref", sourceURL, "import.meta.env", metaEnv[i][1])
		}
	}

	pubEnv := common.RePublicEnv.FindAllString(source, -1)
	if len(pubEnv) > 0 {
		ent.Content.JSFindings["env_public"] += len(pubEnv)
		for i := 0; i < len(pubEnv) && i < 10; i++ {
			common.AppendLeak(ent, "env_public", sourceURL, "public_env", pubEnv[i])
		}
	}
}
