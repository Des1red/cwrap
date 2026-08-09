package jsintel

import (
	"cwrap/internal/recon/jsintel/common"
	"cwrap/internal/recon/knowledge"
	"strings"
)

func learnInfrastructure(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	urls := common.ReURL.FindAllString(source, -1)
	for _, u := range urls {
		if common.IsNoiseURL(u) {
			continue
		}
		ent.Content.JSFindings[knowledge.JSFindingHostURL]++
		if len(ent.Content.JSLeaks) < 8 {
			common.AppendLeak(ent, knowledge.JSFindingHostURL, sourceURL, "url", common.Redact(u, 180))
		}
	}

	internalDomains := common.ReInternalDomain.FindAllStringSubmatch(source, -1)
	if len(internalDomains) > 0 {
		for _, m := range internalDomains {
			label := m[1]
			if label != strings.ToLower(label) {
				continue // camelCase/PascalCase = code identifier, not a hostname
			}
			ent.Content.JSFindings[knowledge.JSFindingHostInternal]++
			if len(ent.Content.JSLeaks) < 8 {
				common.AppendLeak(ent, knowledge.JSFindingHostInternal, sourceURL, "domain", m[0])
			}
		}
	}

	privIPs := common.ReRFC1918.FindAllString(source, -1)
	if len(privIPs) > 0 {
		ent.Content.JSFindings[knowledge.JSFindingHostPrivateIP] += len(privIPs)
		for i := 0; i < len(privIPs) && i < 8; i++ {
			common.AppendLeak(ent, knowledge.JSFindingHostPrivateIP, sourceURL, "ip", privIPs[i])
		}
	}

}
