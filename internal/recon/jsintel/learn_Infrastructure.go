package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"strings"
)

func learnInfrastructure(
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	urls := reURL.FindAllString(source, -1)
	for _, u := range urls {
		if isNoiseURL(u) {
			continue
		}
		ent.Content.JSFindings["host_url"]++
		if len(ent.Content.JSLeaks) < 8 {
			appendLeak(ent, "host_url", sourceURL, "url", redact(u, 180))
		}
	}

	internalDomains := reInternalDomain.FindAllStringSubmatch(source, -1)
	if len(internalDomains) > 0 {
		for _, m := range internalDomains {
			label := m[1]
			if label != strings.ToLower(label) {
				continue // camelCase/PascalCase = code identifier, not a hostname
			}
			ent.Content.JSFindings["host_internal"]++
			if len(ent.Content.JSLeaks) < 8 {
				appendLeak(ent, "host_internal", sourceURL, "domain", m[0])
			}
		}
	}

	privIPs := reRFC1918.FindAllString(source, -1)
	if len(privIPs) > 0 {
		ent.Content.JSFindings["host_private_ip"] += len(privIPs)
		for i := 0; i < len(privIPs) && i < 8; i++ {
			appendLeak(ent, "host_private_ip", sourceURL, "ip", privIPs[i])
		}
	}

}
