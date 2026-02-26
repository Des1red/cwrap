// report/report.go
package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CreateSummary prints an executive summary to the terminal and saves a full,
// in-depth tree report to ./reports/<target>_<timestamp>.report.
// The full file report contains ALL collected data (no redaction, no truncation).
func CreateSummary(k *knowledge.Knowledge) (string, error) {
	if k == nil {
		return "", fmt.Errorf("nil knowledge")
	}

	path, err := CreateFileReport(k)
	// Even if file creation fails, still print a summary of what we have.
	printSummary(os.Stdout, k, path, err)

	return path, err
}

// CreateFileReport writes the full report (tree + deep per-entity analysis) to a file.
// No hidden data, no exceptions.
func CreateFileReport(k *knowledge.Knowledge) (string, error) {
	if k == nil {
		return "", fmt.Errorf("nil knowledge")
	}
	if err := ensureDir(); err != nil {
		return "", err
	}

	f, path, err := createFile(k)
	if err != nil {
		return "", err
	}
	defer f.Close()

	writeFullReport(f, k)

	return path, nil
}

// ---- file plumbing ----

func ensureDir() error {
	return os.MkdirAll("reports", 0o755)
}

func createFile(k *knowledge.Knowledge) (*os.File, string, error) {
	targetPart := sanitizeTargetForFilename(k.Target)
	if targetPart == "" {
		targetPart = "target"
	}

	// Local time (your machine / environment timezone). Filename includes date.
	ts := time.Now().Format("2006-01-02_15-04-05")
	name := fmt.Sprintf("%s_%s.report", targetPart, ts)
	path := filepath.Join("reports", name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, "", err
	}
	return f, path, nil
}

func sanitizeTargetForFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Drop scheme if present.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}

	// Cut at first whitespace.
	if i := strings.IndexAny(s, " \t\r\n"); i >= 0 {
		s = s[:i]
	}

	// Replace unsafe filename characters with '-'.
	repl := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"?", "-",
		"&", "-",
		"=", "-",
		"#", "-",
		"%", "-",
		"@", "-",
		"+", "-",
		",", "-",
		";", "-",
		"(", "-",
		")", "-",
		"[", "-",
		"]", "-",
		"{", "-",
		"}", "-",
		"\"", "-",
		"'", "-",
		"<", "-",
		">", "-",
		"|", "-",
		"*", "-",
		"!", "-",
	)
	s = repl.Replace(s)

	// Collapse repeats.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-._")
	return s
}

// ---- summary ----

func printSummary(w io.Writer, k *knowledge.Knowledge, path string, fileErr error) {
	urls := sortedEntityURLs(k)

	// Global counts / flags
	var (
		entityCount     = len(urls)
		edgeCount       = len(k.Edges)
		globalParamCnt  = len(k.Params)
		hasAuthBoundary = false
		hasOwnership    = false
		possibleIDOR    = 0
		adminSurface    = 0
		jsLeakCount     = 0
	)

	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		if ent.SeenSignal(knowledge.SigAuthBoundary) {
			hasAuthBoundary = true
		}
		if ent.SeenSignal(knowledge.SigObjectOwnership) {
			hasOwnership = true
		}

		for _, p := range ent.Params {
			if p == nil {
				continue
			}
			if p.PossibleIDOR || p.SuspectIDOR || ent.SeenSignal(knowledge.SigPossibleIDOR) {
				possibleIDOR++
				break // count once per entity in summary
			}
		}

		// crude admin surface (signal preferred, then URL heuristic)
		if ent.SeenSignal(knowledge.SigAdminSurface) || strings.Contains(strings.ToLower(ent.URL), "admin") {
			adminSurface++
		}

		jsLeakCount += len(ent.Content.JSLeaks)
	}

	// High risk highlights (short list)
	high := buildHighRiskHighlights(k)

	fmt.Fprintln(w, "========== cwrap Recon Summary ==========")
	if k.Target != "" {
		fmt.Fprintln(w, "Target:", k.Target)
	} else if entityCount > 0 {
		fmt.Fprintln(w, "Target:", urls[0])
	} else {
		fmt.Fprintln(w, "Target: (unknown)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Entities discovered: %d\n", entityCount)
	fmt.Fprintf(w, "Edges discovered:    %d\n", edgeCount)
	fmt.Fprintf(w, "Global parameters:   %d\n", globalParamCnt)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Auth boundary:       %v\n", yesNo(hasAuthBoundary))
	fmt.Fprintf(w, "Ownership boundary:  %v\n", yesNo(hasOwnership))
	fmt.Fprintf(w, "IDOR surfaces:       %d\n", possibleIDOR)
	fmt.Fprintf(w, "Admin surfaces:      %d\n", adminSurface)
	fmt.Fprintf(w, "JS leaks:            %d\n", jsLeakCount)

	if len(high) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "High Risk Findings:")
		for _, s := range high {
			fmt.Fprintln(w, " •", s)
		}
	}

	fmt.Fprintln(w)
	if fileErr == nil && path != "" {
		fmt.Fprintln(w, "Full report saved at:")
		fmt.Fprintln(w, " ", path)
	} else {
		fmt.Fprintln(w, "Full report save failed:")
		if fileErr != nil {
			fmt.Fprintln(w, " ", fileErr.Error())
		} else {
			fmt.Fprintln(w, "  (unknown error)")
		}
	}
	fmt.Fprintln(w, "========================================")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func buildHighRiskHighlights(k *knowledge.Knowledge) []string {
	urls := sortedEntityURLs(k)
	var out []string

	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		// Surface-level: confirmed-ish risks from ParamIntel
		for name, p := range ent.Params {
			if p == nil {
				continue
			}
			if p.PossibleIDOR && p.OwnershipBoundary && p.IDLike {
				out = append(out, fmt.Sprintf("Horizontal privilege escalation suspected: %s (param: %s)", ent.URL, name))
				break
			}
			if p.SuspectIDOR && p.IDLike {
				out = append(out, fmt.Sprintf("Possible IDOR surface: %s (param: %s)", ent.URL, name))
				break
			}
		}

		// Auth bypass hint: any success without creds (identity named "anonymous" is common)
		for _, p := range ent.Params {
			if p == nil {
				continue
			}
			if p.IdentityAccess != nil && p.IdentityAccess["anonymous"] > 0 {
				out = append(out, fmt.Sprintf("Unauthenticated access observed: %s (via param behavior)", ent.URL))
				break
			}
		}

		// JS leak evidence
		if len(ent.Content.JSLeaks) > 0 {
			out = append(out, fmt.Sprintf("Secrets/material found in JS: %s (%d leak(s))", ent.URL, len(ent.Content.JSLeaks)))
		}
	}

	// Dedup + cap to keep summary readable
	out = dedup(out)
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

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
	var walk func(node string, prefix string, isLast bool, stack map[string]bool)
	walk = func(node string, prefix string, isLast bool, stack map[string]bool) {
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
			walk(c.to, nextPrefix, last, stack2)
		}
	}

	stack := map[string]bool{root: true}
	walk(root, "", true, stack)

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

		// Identities (no suppression, no filtering)
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

		// Parameters (no injected-only exclusion)
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
				if len(p.Sources) == 0 {
					fmt.Fprintln(w, "      (none)")
				} else {
					srcs := make([]string, 0, len(p.Sources))
					for s, on := range p.Sources {
						if on {
							srcs = append(srcs, s.String())
						}
					}
					sort.Strings(srcs)
					for _, s := range srcs {
						fmt.Fprintln(w, "      -", s)
					}
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

		// JS Intelligence (no trimming, no redaction)
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

		// Findings (in-file, no exclusions)
		fmt.Fprintln(w, "Findings:")
		findings := deriveFindings(ent)
		if len(findings) == 0 {
			fmt.Fprintln(w, "  (none)")
		} else {
			for _, f := range findings {
				fmt.Fprintln(w, "  -", f)
			}
		}

		// Next Steps (requested: do NOT exclude)
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

// ---- derivation helpers ----

func sortedEntityURLs(k *knowledge.Knowledge) []string {
	urls := make([]string, 0, len(k.Entities))
	for u := range k.Entities {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, on := range m {
		if on {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func activeSignals(ent *knowledge.Entity) []string {
	if ent == nil || len(ent.Signals.Tags) == 0 {
		return nil
	}
	var out []string
	for s, on := range ent.Signals.Tags {
		if on {
			out = append(out, s.String())
		}
	}
	sort.Strings(out)
	return out
}

func identityKindLabel(k knowledge.IdentityKind) string {
	switch k {
	case knowledge.IdentityUnknown:
		return "IdentityUnknown"
	case knowledge.IdentityNone:
		return "IdentityNone"
	case knowledge.IdentityBootstrap:
		return "IdentityBootstrap"
	case knowledge.IdentityUser:
		return "IdentityUser"
	case knowledge.IdentityElevated:
		return "IdentityElevated"
	case knowledge.IdentityInvalid:
		return "IdentityInvalid"
	default:
		return "IdentityKind(?)"
	}
}

func emptyAsNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func writeStringIntMap(w io.Writer, prefix string, m map[string]int) {
	if len(m) == 0 {
		fmt.Fprintln(w, prefix+"(none)")
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s: %d\n", prefix, k, m[k])
	}
}

func deriveFindings(ent *knowledge.Entity) []string {
	var out []string
	if ent == nil {
		return out
	}

	// Signals-based findings
	if ent.SeenSignal(knowledge.SigAdminSurface) {
		out = append(out, "Administrative surface detected")
	}
	if ent.SeenSignal(knowledge.SigFileUpload) {
		out = append(out, "File upload surface detected")
	}
	if ent.SeenSignal(knowledge.SigSensitiveKeyword) {
		out = append(out, "Sensitive keywords detected in content/JS")
	}
	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		out = append(out, "Authentication/authorization boundary observed")
	}
	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		out = append(out, "Object ownership enforcement observed")
	}

	// Param-based findings
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

		if p.PossibleIDOR && p.OwnershipBoundary && p.IDLike {
			out = append(out, fmt.Sprintf("Horizontal privilege escalation possible via param: %s", name))
		}
		if p.SuspectIDOR && p.IDLike {
			out = append(out, fmt.Sprintf("Suspect IDOR surface via param: %s", name))
		}
		if p.Enumerable && p.LikelyObjectAccess {
			out = append(out, fmt.Sprintf("Object enumeration possible via param: %s", name))
		}
		if p.DebugLike {
			out = append(out, fmt.Sprintf("Debug functionality exposed via param: %s", name))
		}
		if p.TokenLike {
			out = append(out, fmt.Sprintf("Token-like parameter observed: %s", name))
		}

		// Unauthenticated access hint
		if p.IdentityAccess != nil && p.IdentityAccess["anonymous"] > 0 {
			out = append(out, fmt.Sprintf("Unauthenticated access observed (identity: anonymous) via param behavior: %s", name))
		}
	}

	// JS leaks are always findings in full report
	if len(ent.Content.JSLeaks) > 0 {
		out = append(out, fmt.Sprintf("JS leaks present: %d", len(ent.Content.JSLeaks)))
	}

	out = dedup(out)
	sort.Strings(out)
	return out
}

func deriveNextSteps(ent *knowledge.Entity) []string {
	var out []string
	if ent == nil {
		return out
	}

	// Parameter-driven suggestions (no exclusions)
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

		if p.Enumerable {
			out = append(out, "Enumerate "+name+" sequentially")
		}
		if p.PossibleIDOR || p.SuspectIDOR {
			out = append(out, "Attempt cross-identity object access via "+name)
		}
		if p.IDLike && p.OwnershipBoundary {
			out = append(out, "Test horizontal privilege escalation using "+name)
		}
		if p.AuthBoundary && !p.OwnershipBoundary {
			out = append(out, "Test vertical privilege escalation / role boundary using "+name)
		}
		if p.TokenLike {
			out = append(out, "Attempt token reuse / swapping / fixation using "+name)
		}
		if p.DebugLike {
			out = append(out, "Probe debug flags / verbose errors using "+name)
		}
	}

	// Auth-phase suggestions
	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		out = append(out,
			"Test weak credentials and default accounts",
			"Attempt username enumeration",
			"Test auth bypass headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)",
		)
	}

	// Ownership-phase suggestions
	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		out = append(out, "Attempt cross-user object access (IDOR) across identities")
	}

	// JS leaks suggestions
	if len(ent.Content.JSLeaks) > 0 || len(ent.Content.JSFindings) > 0 {
		out = append(out, "Review JS findings for secrets, endpoints, role gates, and client-side auth assumptions")
	}

	out = dedup(out)
	sort.Strings(out)
	return out
}
