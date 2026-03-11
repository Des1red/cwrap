package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"io"
	"sort"
	"time"
)

// ---- full report ----

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

	// Signals rollup
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

	fmt.Fprintln(w)
}

func writeDiscoveryTree(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "DISCOVERY TREE")
	fmt.Fprintln(w, "------------------------------------------------")

	// Build adjacency from edges.
	type child struct {
		to    string
		etype knowledge.EdgeType
	}
	adj := make(map[string][]child)

	// also ensure nodes exist even if no edges
	for u := range k.Entities {
		if _, ok := adj[u]; !ok {
			adj[u] = nil
		}
	}

	for _, e := range k.Edges {
		adj[e.From] = append(adj[e.From], child{to: e.To, etype: e.Type})
		// ensure target key exists
		if _, ok := adj[e.To]; !ok {
			adj[e.To] = nil
		}
	}

	// Sort children deterministically.
	for from := range adj {
		cs := adj[from]
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].to == cs[j].to {
				return cs[i].etype < cs[j].etype
			}
			return cs[i].to < cs[j].to
		})
		adj[from] = cs
	}

	// Pick root:
	// Prefer k.Target if it matches an entity key; otherwise use lexicographically first entity.
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

	// DFS with cycle protection (graph can have cycles).
	var walk func(node string, prefix string, stack map[string]bool)
	walk = func(node string, prefix string, stack map[string]bool) {
		children := adj[node]
		for i, c := range children {
			last := i == len(children)-1

			branch := "├── "
			nextPrefix := prefix + "│   "
			if last {
				branch = "└── "
				nextPrefix = prefix + "    "
			}

			edgeTag := edgeTypeLabel(c.etype)
			line := fmt.Sprintf("%s%s%s", prefix, branch, c.to)
			if edgeTag != "" {
				line += "  [" + edgeTag + "]"
			}

			// cycle marker
			if stack[c.to] {
				line += "  (cycle)"
				fmt.Fprintln(w, line)
				continue
			}

			fmt.Fprintln(w, line)

			// recurse
			stack2 := copySet(stack)
			stack2[c.to] = true
			walk(c.to, nextPrefix, stack2)
		}
	}

	stack := map[string]bool{root: true}
	walk(root, "", stack)

	fmt.Fprintln(w)
}

func edgeTypeLabel(t knowledge.EdgeType) string {
	switch t {
	case knowledge.EdgeDiscoveredFromHTML:
		return "html"
	case knowledge.EdgeDiscoveredFromJS:
		return "js"
	case knowledge.EdgeFormAction:
		return "form"
	default:
		return "edge"
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
	fmt.Fprintln(w, "ENTITY INTELLIGENCE (DETAILED)")
	fmt.Fprintln(w, "------------------------------------------------")

	urls := sortedEntityURLs(k)
	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, "[ENTITY]", ent.URL)

		// State
		fmt.Fprintln(w, "State:")
		fmt.Fprintf(w, "  Seen:       %v\n", ent.State.Seen)
		fmt.Fprintf(w, "  ProbeCount: %d\n", ent.State.ProbeCount)

		// HTTP
		fmt.Fprintln(w, "HTTP:")
		fmt.Fprintf(w, "  AuthLikely:  %v\n", ent.HTTP.AuthLikely)
		fmt.Fprintf(w, "  CSRFPresent: %v\n", ent.HTTP.CSRFPresent)

		methods := sortedKeys(ent.HTTP.Methods)
		fmt.Fprintln(w, "  Methods:")
		if len(methods) == 0 {
			fmt.Fprintln(w, "    (none)")
		} else {
			for _, m := range methods {
				fmt.Fprintln(w, "    -", m)
			}
		}

		headers := sortedKeys(ent.HTTP.Headers)
		fmt.Fprintln(w, "  Headers:")
		if len(headers) == 0 {
			fmt.Fprintln(w, "    (none)")
		} else {
			for _, h := range headers {
				fmt.Fprintln(w, "    -", h)
			}
		}

		// Content
		fmt.Fprintln(w, "Content:")
		fmt.Fprintf(w, "  LooksLikeHTML: %v\n", ent.Content.LooksLikeHTML)
		fmt.Fprintf(w, "  LooksLikeJSON: %v\n", ent.Content.LooksLikeJSON)
		fmt.Fprintf(w, "  LooksLikeXML:  %v\n", ent.Content.LooksLikeXML)

		fmt.Fprintln(w, "  Statuses:")
		if len(ent.Content.Statuses) == 0 {
			fmt.Fprintln(w, "    (none)")
		} else {
			codes := make([]int, 0, len(ent.Content.Statuses))
			for c := range ent.Content.Statuses {
				codes = append(codes, c)
			}
			sort.Ints(codes)
			for _, c := range codes {
				fmt.Fprintf(w, "    %d: %d\n", c, ent.Content.Statuses[c])
			}
		}

		fmt.Fprintln(w, "  MIMEs:")
		if len(ent.Content.MIMEs) == 0 {
			fmt.Fprintln(w, "    (none)")
		} else {
			mimes := make([]string, 0, len(ent.Content.MIMEs))
			for m := range ent.Content.MIMEs {
				mimes = append(mimes, m)
			}
			sort.Strings(mimes)
			for _, m := range mimes {
				fmt.Fprintf(w, "    %s: %d\n", m, ent.Content.MIMEs[m])
			}
		}

		// Signals
		fmt.Fprintln(w, "Signals:")
		sigs := activeSignals(ent)
		if len(sigs) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
			for _, s := range sigs {
				fmt.Fprintln(w, "  -", s)
			}
		}

		// Session (raw cookies/tokens)
		fmt.Fprintln(w, "Session:")
		fmt.Fprintf(w, "  Used:   %v\n", ent.SessionUsed)
		fmt.Fprintf(w, "  Issued: %v\n", ent.SessionIssued)
		fmt.Fprintln(w, "  Cookies:")
		if len(ent.SessionCookies) == 0 {
			fmt.Fprintln(w, "    (none)")
		} else {
			names := make([]string, 0, len(ent.SessionCookies))
			for n := range ent.SessionCookies {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				// Option A: raw value, no masking.
				fmt.Fprintf(w, "    - %s=%s\n", n, ent.SessionCookies[n])
			}
		}

		// Identities
		fmt.Fprintln(w, "Identities:")
		if len(ent.Identities) == 0 && len(ent.IdentityIndex) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
			// Prefer stable list: union of names (ent.Identities is name->id).
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
				fmt.Fprintln(w, "  Name:", id.Name)
				fmt.Fprintln(w, "    Kind:", identityKindLabel(id.Kind))
				if id.Role != "" {
					fmt.Fprintln(w, "    Role:", id.Role)
				} else {
					fmt.Fprintln(w, "    Role:", "(none)")
				}
				fmt.Fprintln(w, "    Effective:", id.Effective)
				fmt.Fprintln(w, "    SentCreds:", id.SentCreds)
				fmt.Fprintln(w, "    Rejected:", id.Rejected)
				fmt.Fprintln(w, "    IssuedByServer:", id.IssuedByServer)
				fmt.Fprintln(w, "    AuthScheme:", emptyAsNone(id.AuthScheme))
				fmt.Fprintln(w, "    HasCSRF:", id.HasCSRF)
				fmt.Fprintln(w, "    CookieNames:")
				if len(id.CookieNames) == 0 {
					fmt.Fprintln(w, "      (none)")
				} else {
					for _, cn := range id.CookieNames {
						fmt.Fprintln(w, "      -", cn)
					}
				}
			}
		}

		// Parameters
		fmt.Fprintln(w, "Parameters:")
		if len(ent.Params) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
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
				fmt.Fprintln(w, "  Name:", p.Name)

				// Sources
				fmt.Fprintln(w, "    Sources:")

				srcs := make([]string, 0)
				for s, on := range p.Sources {
					if on {
						srcs = append(srcs, paramSourceLabel(p, s))
					}
				}
				// If no source recorded, treat as scanner injected
				if len(srcs) == 0 {
					srcs = append(srcs, paramSourceLabel(p, knowledge.ParamInjected))
				}
				sort.Strings(srcs)
				for _, s := range srcs {
					fmt.Fprintln(w, "      -", s)
				}

				// Heuristics
				fmt.Fprintln(w, "    Heuristics:")
				fmt.Fprintln(w, "      IDLike:", p.IDLike)
				fmt.Fprintln(w, "      TokenLike:", p.TokenLike)
				fmt.Fprintln(w, "      DebugLike:", p.DebugLike)
				fmt.Fprintln(w, "      LikelyReflection:", p.LikelyReflection)
				fmt.Fprintln(w, "      LikelyObjectAccess:", p.LikelyObjectAccess)

				// Evidence / boundaries
				fmt.Fprintln(w, "    Evidence:")
				fmt.Fprintln(w, "      Enumerable:", p.Enumerable)
				fmt.Fprintln(w, "      AuthBoundary:", p.AuthBoundary)
				fmt.Fprintln(w, "      OwnershipBoundary:", p.OwnershipBoundary)
				fmt.Fprintln(w, "      PossibleIDOR:", p.PossibleIDOR)
				fmt.Fprintln(w, "      SuspectIDOR:", p.SuspectIDOR)
				fmt.Fprintln(w, "      Interest:", p.Interest)

				// Observed changes
				fmt.Fprintln(w, "    ObservedChanges:")
				if len(p.ObservedChanges) == 0 {
					fmt.Fprintln(w, "      (none)")
				} else {
					keys := make([]string, 0, len(p.ObservedChanges))
					for k := range p.ObservedChanges {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						fmt.Fprintln(w, "      -", k)
					}
				}

				// Identity access/denied maps
				fmt.Fprintln(w, "    IdentityAccess:")
				writeStringIntMap(w, "      ", p.IdentityAccess)
				fmt.Fprintln(w, "    IdentityDenied:")
				writeStringIntMap(w, "      ", p.IdentityDenied)
			}
		}

		// JS Intelligence
		fmt.Fprintln(w, "JS Intelligence:")
		if len(ent.Content.JSFindings) == 0 && len(ent.Content.JSLeaks) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
			fmt.Fprintln(w, "  Findings:")
			if len(ent.Content.JSFindings) == 0 {
				fmt.Fprintln(w, "    (none)")
			} else {
				keys := make([]string, 0, len(ent.Content.JSFindings))
				for k := range ent.Content.JSFindings {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(w, "    - %s: %d\n", k, ent.Content.JSFindings[k])
				}
			}

			fmt.Fprintln(w, "  Leaks:")
			if len(ent.Content.JSLeaks) == 0 {
				fmt.Fprintln(w, "    (none)")
			} else {
				for _, leak := range ent.Content.JSLeaks {
					fmt.Fprintln(w, "    - Kind:", leak.Kind)
					fmt.Fprintln(w, "      Source:", leak.Source)
					fmt.Fprintln(w, "      Key:", emptyAsNone(leak.Key))
					// Option A: raw value, no masking.
					fmt.Fprintln(w, "      Value:", leak.Value)
				}
			}
		}

		// Findings
		fmt.Fprintln(w, "Findings:")
		findings := deriveFindings(ent)
		if len(findings) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
			for _, f := range findings {
				fmt.Fprintln(w, "  -", f)
			}
		}

		// Next Steps
		fmt.Fprintln(w, "Next Steps:")
		steps := deriveNextSteps(ent)
		if len(steps) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
			for _, s := range steps {
				fmt.Fprintln(w, "  -", s)
			}
		}
	}
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
