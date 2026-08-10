package report

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"fmt"
	"io"
	"sort"
)

func writeGlobalStats(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "GLOBAL STATS")
	fmt.Fprintln(w, "------------------------------------------------")

	urls := common.SortedEntityURLs(k)

	abnormalResponseCount := 0
	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		abnormalResponseCount += len(ent.AbnormalResponses)
	}

	fmt.Fprintf(w, "Entities:          %d\n", len(urls))
	fmt.Fprintf(w, "Static assets:     %d\n", len(k.StaticAssets))
	fmt.Fprintf(w, "Edges:             %d\n", len(k.Edges))
	fmt.Fprintf(w, "Global parameters: %d\n", len(k.Params))
	fmt.Fprintf(w, "Abnormal responses:  %d\n", abnormalResponseCount)

	sigCounts := make(map[string]int)
	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}
		for s, on := range ent.Signals.Tags {
			if on {
				sigCounts[s.String()]++
			}
		}
	}
	if len(sigCounts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Signals (count of entities tagged):")
		keys := make([]string, 0, len(sigCounts))
		for k := range sigCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  - %s: %d\n", k, sigCounts[k])
		}
	}

	// Public endpoints
	var publicURLs []string
	for _, u := range urls {
		ent := k.Entities[u]
		if ent != nil && ent.Signals.Tags[knowledge.SigPublicAccess] {
			if ent.State.IsSPAFallback {
				continue
			}
			publicURLs = append(publicURLs, u)
		}
	}
	if len(publicURLs) > 0 {
		fmt.Fprintf(w, "Public endpoints:  %d\n", len(publicURLs))
		sort.Strings(publicURLs)
		for _, u := range publicURLs {
			fmt.Fprintf(w, "  - %s\n", u)
		}
	}
	// Tech fingerprinting — deduplicated across all entities
	tech := make(map[string]string)
	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}
		for k, v := range ent.HTTP.Tech {
			if _, seen := tech[k]; !seen {
				tech[k] = v
			}
		}
	}
	if len(tech) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Tech:")
		techKeys := make([]string, 0, len(tech))
		for k := range tech {
			techKeys = append(techKeys, k)
		}
		sort.Strings(techKeys)
		for _, k := range techKeys {
			fmt.Fprintf(w, "  - %s: %s\n", k, tech[k])
		}
	}

	fmt.Fprintln(w)
}

func writeContactInfo(w io.Writer, k *knowledge.Knowledge) {
	if len(k.Emails) == 0 && len(k.Phones) == 0 {
		return
	}
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "CONTACT INFO")
	fmt.Fprintln(w, "------------------------------------------------")

	if len(k.Emails) > 0 {
		emails := make([]string, 0, len(k.Emails))
		for e := range k.Emails {
			emails = append(emails, e)
		}
		sort.Strings(emails)
		for _, e := range emails {
			fmt.Fprintf(w, "  email: %s\n", e)
		}
	}

	if len(k.Phones) > 0 {
		phones := make([]string, 0, len(k.Phones))
		for p := range k.Phones {
			phones = append(phones, p)
		}
		sort.Strings(phones)
		for _, p := range phones {
			fmt.Fprintf(w, "  tel:   %s\n", p)
		}
	}
	fmt.Fprintln(w)
}

func writeIdentityVault(w io.Writer, k *knowledge.Knowledge) {
	if len(k.DiscoveredIdentities) == 0 {
		return
	}
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "IDENTITY VAULT")
	fmt.Fprintln(w, "------------------------------------------------")
	names := make([]string, 0, len(k.DiscoveredIdentities))
	for n := range k.DiscoveredIdentities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %s:\n", name)
		cookies := k.DiscoveredIdentities[name]
		cnames := make([]string, 0, len(cookies))
		for cn := range cookies {
			cnames = append(cnames, cn)
		}
		sort.Strings(cnames)
		for _, cn := range cnames {
			fmt.Fprintf(w, "    %s=%s\n", cn, cookies[cn])
		}
	}
	fmt.Fprintln(w)
}

func writeStaticAssets(w io.Writer, k *knowledge.Knowledge) {
	if len(k.StaticAssets) == 0 {
		return
	}

	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "STATIC ASSETS")
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintf(w, "Count: %d\n\n", len(k.StaticAssets))

	urls := make([]string, 0, len(k.StaticAssets))
	for u := range k.StaticAssets {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	for _, u := range urls {
		fmt.Fprintf(w, "  - %s\n", u)
	}
	fmt.Fprintln(w)
}
