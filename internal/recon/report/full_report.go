package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

func writeFullReport(w io.Writer, k *knowledge.Knowledge) {
	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Fprintln(w, "========== CWRAP FULL RECON REPORT ==========")
	if k.Target != "" {
		fmt.Fprintln(w, "Target:   ", k.Target)
	}
	fmt.Fprintln(w, "Generated:", now)
	fmt.Fprintln(w)

	writeGlobalStats(w, k)
	writeDiscoveryTree(w, k)
	writeEntityDetails(w, k)
	writeIdentityVault(w, k)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=============== END OF REPORT ===============")
}

func writeGlobalStats(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "GLOBAL STATS")
	fmt.Fprintln(w, "------------------------------------------------")

	urls := sortedEntityURLs(k)
	fmt.Fprintf(w, "Entities:          %d\n", len(urls))
	fmt.Fprintf(w, "Edges:             %d\n", len(k.Edges))
	fmt.Fprintf(w, "Global parameters: %d\n", len(k.Params))

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

	fmt.Fprintln(w)
}

func writeDiscoveryTree(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "DISCOVERY TREE")
	fmt.Fprintln(w, "------------------------------------------------")

	type child struct {
		to    string
		etype knowledge.EdgeType
	}
	adj := make(map[string][]child)
	for u := range k.Entities {
		if _, ok := adj[u]; !ok {
			adj[u] = nil
		}
	}
	for _, e := range k.Edges {
		adj[e.From] = append(adj[e.From], child{to: e.To, etype: e.Type})
		if _, ok := adj[e.To]; !ok {
			adj[e.To] = nil
		}
	}
	for from := range adj {
		seen := map[string]bool{}
		deduped := make([]child, 0, len(adj[from]))
		for _, c := range adj[from] {
			key := c.to + "|" + edgeTypeLabel(c.etype)
			if !seen[key] {
				seen[key] = true
				deduped = append(deduped, c)
			}
		}
		adj[from] = deduped
	}

	root := ""
	if k.Target != "" {
		if _, ok := k.Entities[k.Target]; ok {
			root = k.Target
		}
	}
	if root == "" {
		urls := sortedEntityURLs(k)
		if len(urls) > 0 {
			root = urls[0]
		}
	}
	if root == "" {
		fmt.Fprintln(w, "(no entities)")
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w, root)
	visited := map[string]bool{root: true}
	var walk func(node string, prefix string)
	walk = func(node string, prefix string) {
		children := adj[node]
		for i, c := range children {
			last := i == len(children)-1
			branch := "├── "
			nextPrefix := prefix + "│   "
			if last {
				branch = "└── "
				nextPrefix = prefix + "    "
			}
			line := fmt.Sprintf("%s%s%s", prefix, branch, c.to)
			if tag := edgeTypeLabel(c.etype); tag != "" {
				line += "  [" + tag + "]"
			}
			if visited[c.to] {
				line += "  (seen)"
				fmt.Fprintln(w, line)
				continue
			}
			fmt.Fprintln(w, line)
			visited[c.to] = true
			walk(c.to, nextPrefix)
		}
	}
	walk(root, "")
	fmt.Fprintln(w)
}

func edgeTypeLabel(t knowledge.EdgeType) string {
	switch t {
	case knowledge.EdgeDiscoveredFromHTML:
		return knowledge.EdgeLabelHTML
	case knowledge.EdgeDiscoveredFromJS:
		return knowledge.EdgeLabelJS
	case knowledge.EdgeFormAction:
		return knowledge.EdgeLabelForm
	default:
		return knowledge.EdgeLabelEdge
	}
}

func copySet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func writeEntityDetails(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "ENTITY INTELLIGENCE")
	fmt.Fprintln(w, "------------------------------------------------")

	for _, u := range entityURLsBySignalCount(k) {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, "[ENTITY]", ent.URL)
		fmt.Fprintf(w, "  Probes: %d\n", ent.State.ProbeCount)

		// HTTP — only print non-empty/true fields
		methods := sortedKeys(ent.HTTP.Methods)
		if len(methods) > 0 {
			fmt.Fprintf(w, "  Methods: %v\n", methods)
		}
		if ent.HTTP.AuthLikely {
			fmt.Fprintln(w, "  AuthLikely: "+strconv.FormatBool(ent.HTTP.AuthLikely))
		}
		if ent.HTTP.CSRFPresent {
			fmt.Fprintln(w, "  CSRFPresent: "+strconv.FormatBool(ent.HTTP.CSRFPresent))
		}

		// Content — only print true content type
		if ent.Content.LooksLikeHTML {
			fmt.Fprintln(w, "  Content: HTML")
		} else if ent.Content.LooksLikeJSON {
			fmt.Fprintln(w, "  Content: JSON")
		} else if ent.Content.LooksLikeXML {
			fmt.Fprintln(w, "  Content: XML")
		}

		// Statuses
		if len(ent.Content.Statuses) > 0 {
			codes := make([]int, 0, len(ent.Content.Statuses))
			for c := range ent.Content.Statuses {
				codes = append(codes, c)
			}
			sort.Ints(codes)
			fmt.Fprint(w, "  Statuses:")
			for _, c := range codes {
				fmt.Fprintf(w, " %d×%d", c, ent.Content.Statuses[c])
			}
			fmt.Fprintln(w)
		}

		// Signals
		if sigs := activeSignals(ent); len(sigs) > 0 {
			fmt.Fprintf(w, "  Signals: %v\n", sigs)
		}

		// Session — only if something happened
		if ent.SessionUsed || ent.SessionIssued || len(ent.SessionCookies) > 0 {
			fmt.Fprintln(w, "  Session:")
			if ent.SessionUsed {
				fmt.Fprintln(w, "    Used: "+strconv.FormatBool(ent.SessionUsed))
			}
			if ent.SessionIssued {
				fmt.Fprintln(w, "    Issued: "+strconv.FormatBool(ent.SessionIssued))
			}
			if len(ent.SessionCookies) > 0 {
				names := make([]string, 0, len(ent.SessionCookies))
				for n := range ent.SessionCookies {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					fmt.Fprintf(w, "    - %s=%s\n", n, ent.SessionCookies[n])
				}
			}
		}

		// Identities — only print fields that carry information
		if len(ent.Identities) > 0 {
			fmt.Fprintln(w, "  Identities:")
			names := make([]string, 0, len(ent.Identities))
			for n := range ent.Identities {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, name := range names {
				id := ent.Identities[name]
				if id == nil {
					continue
				}
				tags := []string{}
				tags = append(tags, identityKindLabel(id.Kind))
				if id.SentCreds {
					tags = append(tags, knowledge.IdentityTagCreds)
				}
				if id.Rejected {
					tags = append(tags, knowledge.IdentityTagRejected)
				}
				if id.IssuedByServer {
					tags = append(tags, knowledge.IdentityTagIssuedToken)
				}
				if id.Effective {
					tags = append(tags, knowledge.IdentityTagEffective)
				}
				if id.Role != "" {
					tags = append(tags, "role="+id.Role)
				}
				if id.UserID != "" {
					tags = append(tags, "uid="+id.UserID)
				}
				if id.Expiry != "" {
					tags = append(tags, "exp="+id.Expiry)
				}
				if id.AuthScheme != "" {
					tags = append(tags, "scheme="+id.AuthScheme)
				}
				if id.HasCSRF {
					tags = append(tags, knowledge.IdentityTagCSRF)
					if id.CSRFToken != "" {
						tags = append(tags, knowledge.IdentityTagCSRFToken+"="+id.CSRFToken)
					}
					if id.CSRFHeader != "" {
						tags = append(tags, knowledge.IdentityTagCSRFHeader+"="+id.CSRFHeader)
					}
					if id.CSRFCookieName != "" {
						tags = append(tags, knowledge.IdentityTagCSRFCookieName+"="+id.CSRFCookieName)
					}
				}
				fmt.Fprintf(w, "    %s: %v\n", name, tags)
				if len(id.CookieNames) > 0 {
					fmt.Fprintf(w, "      cookies: %v\n", id.CookieNames)
				}
			}
		}

		// Parameters — skip entirely if injected-only with zero evidence
		hasInterestingParams := false
		for _, p := range ent.Params {
			if p == nil {
				continue
			}
			if paramHasEvidence(p) {
				hasInterestingParams = true
				break
			}
		}

		if hasInterestingParams || hasNonInjectedParams(ent) {
			fmt.Fprintln(w, "  Parameters:")
			pnames := make([]string, 0, len(ent.Params))
			for n := range ent.Params {
				pnames = append(pnames, n)
			}
			sort.Strings(pnames)

			for _, name := range pnames {
				p := ent.Params[name]
				if p == nil {
					continue
				}

				// skip injected params with zero evidence entirely
				if p.InjectedOnly() && !paramHasEvidence(p) {
					continue
				}

				src := paramSourceShort(p)
				tags := []string{src}
				if p.IDLike {
					tags = append(tags, knowledge.ParamTagIDLike)
				}
				if p.TokenLike {
					tags = append(tags, knowledge.ParamTagTokenLike)
				}
				if p.DebugLike {
					tags = append(tags, knowledge.ParamTagDebugLike)
				}
				if p.LikelyReflection {
					tags = append(tags, knowledge.ParamTagReflection)
				}
				if p.LikelyObjectAccess {
					tags = append(tags, knowledge.ParamTagObjectAccess)
				}
				if p.Enumerable {
					tags = append(tags, knowledge.ParamTagEnumerable)
				}
				if p.AuthBoundary {
					tags = append(tags, knowledge.ParamTagAuthBoundary)
				}
				if p.OwnershipBoundary {
					tags = append(tags, knowledge.ParamTagOwnershipBoundary)
				}
				if p.PossibleIDOR {
					tags = append(tags, knowledge.ParamTagPossibleIDOR)
				}
				if p.SuspectIDOR {
					tags = append(tags, knowledge.ParamTagSuspectIDOR)
				}
				if p.Interest > 0 {
					tags = append(tags, fmt.Sprintf("interest=%d", p.Interest))
				}

				fmt.Fprintf(w, "    %s: %v\n", name, tags)

				if len(p.ObservedChanges) > 0 {
					keys := make([]string, 0, len(p.ObservedChanges))
					for k := range p.ObservedChanges {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					fmt.Fprintf(w, "      changes: %v\n", keys)
				}

				if len(p.IdentityAccess) > 0 {
					fmt.Fprintf(w, "      access: %v\n", p.IdentityAccess)
				}
				if len(p.IdentityDenied) > 0 {
					fmt.Fprintf(w, "      denied: %v\n", p.IdentityDenied)
				}
			}
		}

		// JS Intelligence — only if something found
		if len(ent.Content.JSFindings) > 0 || len(ent.Content.JSLeaks) > 0 {
			fmt.Fprintln(w, "  JS Intelligence:")
			if len(ent.Content.JSFindings) > 0 {
				keys := make([]string, 0, len(ent.Content.JSFindings))
				for k := range ent.Content.JSFindings {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(w, "    %s: %d\n", k, ent.Content.JSFindings[k])
				}
			}
			for _, leak := range ent.Content.JSLeaks {
				fmt.Fprintf(w, "    [%s] %s: %s\n", leak.Kind, leak.Key, leak.Value)
			}
		}

		// Findings and Next Steps — always print if present
		findings := deriveFindings(ent)
		if len(findings) > 0 {
			fmt.Fprintln(w, "  Findings:")
			for _, f := range findings {
				fmt.Fprintln(w, "    !", f)
			}
		}

		steps := deriveNextSteps(ent)
		if len(steps) > 0 {
			fmt.Fprintln(w, "  Next Steps:")
			for _, s := range steps {
				fmt.Fprintln(w, "    >", s)
			}
		}
	}
}

// paramHasEvidence returns true if a param has any non-default evidence worth reporting.
func paramHasEvidence(p *knowledge.ParamIntel) bool {
	if p.LikelyReflection || p.LikelyObjectAccess || p.Enumerable {
		return true
	}
	if p.AuthBoundary || p.OwnershipBoundary || p.PossibleIDOR || p.SuspectIDOR {
		return true
	}
	if p.Interest > 0 {
		return true
	}
	if len(p.ObservedChanges) > 0 {
		return true
	}
	// injected params with only access/denied maps don't have real evidence —
	// those maps just reflect entity-level auth, not param-specific behavior
	if p.InjectedOnly() {
		return false
	}
	// access is only meaningful if there's also denial — mixed access = auth boundary evidence
	if len(p.IdentityAccess) > 0 && len(p.IdentityDenied) > 0 {
		return true
	}
	// denial alone is always meaningful
	if len(p.IdentityDenied) > 0 {
		return true
	}
	return false
}

// hasNonInjectedParams returns true if entity has any params from real sources.
func hasNonInjectedParams(ent *knowledge.Entity) bool {
	for _, p := range ent.Params {
		if p == nil {
			continue
		}
		if !p.InjectedOnly() {
			return true
		}
	}
	return false
}

func paramSourceShort(p *knowledge.ParamIntel) string {
	if p.Sources[knowledge.ParamQuery] {
		return "query"
	}
	if p.Sources[knowledge.ParamForm] {
		return "form"
	}
	if p.Sources[knowledge.ParamJSON] {
		return "json"
	}
	if p.Sources[knowledge.ParamPath] {
		return "path"
	}
	return "injected"
}

func paramSourceLabel(p *knowledge.ParamIntel, src knowledge.ParamSource) string {
	switch src {
	case knowledge.ParamInjected:
		if p.DiscoveryReason != "" {
			return "injected (scanner discovery: " + p.DiscoveryReason + ")"
		}
		return "injected (scanner discovery)"
	case knowledge.ParamQuery:
		return "query"
	case knowledge.ParamForm:
		return "form"
	case knowledge.ParamJSON:
		return "json"
	case knowledge.ParamPath:
		return "path"
	default:
		return "unknown"
	}
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
