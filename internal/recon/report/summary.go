package report

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"fmt"
	"io"
	"strings"
)

// ---- summary ----

func printSummary(w io.Writer, k *knowledge.Knowledge, path string, fileErr error) {
	urls := common.SortedEntityURLs(k)

	// Global counts / flags
	var (
		entityCount           = len(urls)
		edgeCount             = len(k.Edges)
		globalParamCnt        = len(k.Params)
		hasAuthBoundary       = false
		hasRoleBoundary       = false
		hasOwnership          = false
		hasCredlessIssuance   = false
		possibleIDOR          = 0
		adminSurface          = 0
		jsLeakCount           = 0
		abnormalResponseCount = 0
	)

	for _, u := range urls {
		ent := k.Entities[u]
		if ent == nil {
			continue
		}

		if ent.State.IsSPAFallback {
			continue
		}

		if ent.SeenSignal(knowledge.SigAuthBoundary) {
			hasAuthBoundary = true
		}
		if ent.SeenSignal(knowledge.SigObjectOwnership) {
			hasOwnership = true
		}

		if ent.SeenSignal(knowledge.SigRoleBoundary) {
			hasRoleBoundary = true
		}
		if ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
			hasCredlessIssuance = true
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
		abnormalResponseCount += len(ent.AbnormalResponses)
		jsLeakCount += len(ent.Content.JSLeaks)
	}

	// High risk highlights (short list)
	high := buildHighRiskHighlights(k)

	fmt.Fprintln(w, common.Bold(common.Cyan("========== cwrap Recon Summary ==========")))
	if k.Target != "" {
		fmt.Fprintln(w, "Target:", common.Bold(k.Target))
	} else if entityCount > 0 {
		fmt.Fprintln(w, "Target:", common.Bold(urls[0]))
	} else {
		fmt.Fprintln(w, "Target:", common.Bold("(unknown)"))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Entities discovered: %d\n", entityCount)
	fmt.Fprintf(w, "Edges discovered:    %d\n", edgeCount)
	fmt.Fprintf(w, "Global parameters:   %d\n", globalParamCnt)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Auth boundary:       %s\n", yesNo(hasAuthBoundary))
	fmt.Fprintf(w, "Role boundary:       %s\n", yesNo(hasRoleBoundary))
	fmt.Fprintf(w, "Ownership boundary:  %s\n", yesNo(hasOwnership))
	fmt.Fprintf(w, "IDOR surfaces:       %s\n", riskCount(possibleIDOR))
	fmt.Fprintf(w, "Admin surfaces:      %s\n", riskCount(adminSurface))
	fmt.Fprintf(w, "JS leaks:            %s\n", riskCount(jsLeakCount))
	fmt.Fprintf(w, "Abnormal responses: %s\n", riskCount(abnormalResponseCount))
	fmt.Fprintf(w, "Credentialless issuance: %s\n", yesNo(hasCredlessIssuance))
	public := 0
	for _, u := range urls {
		ent := k.Entities[u]
		if ent != nil && !ent.State.IsSPAFallback && ent.Signals.Tags[knowledge.SigPublicAccess] {
			public++
		}
	}
	fmt.Fprintf(w, "Public endpoints:    %d\n", public)

	if len(high) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, common.Bold(common.Red("High Risk Findings:")))
		for _, s := range high {
			fmt.Fprintln(w, common.Red(" • "+s))
		}
	}

	fmt.Fprintln(w)
	if fileErr == nil && path != "" {
		fmt.Fprintln(w, common.Green("Full report saved at:"))
		fmt.Fprintln(w, " ", common.Bold(path))
	} else {
		fmt.Fprintln(w, common.Bold(common.Red("Full report save failed:")))
		if fileErr != nil {
			fmt.Fprintln(w, " ", common.Red(fileErr.Error()))
		} else {
			fmt.Fprintln(w, common.Red("  (unknown error)"))
		}
	}
	fmt.Fprintln(w, common.Bold(common.Cyan("========================================")))
}

func yesNo(b bool) string {
	if b {
		return common.Red("yes")
	}
	return common.Green("no")
}

func riskCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n > 0 {
		return common.Red(s)
	}
	return common.Green(s)
}

func buildHighRiskHighlights(k *knowledge.Knowledge) []string {
	urls := common.SortedEntityURLs(k)
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
			if p.IdentityAccess != nil && p.IdentityAccess["anonymous"] > 0 && len(p.IdentityDenied) > 0 {
				out = append(out, fmt.Sprintf("Unauthenticated access observed: %s (via param behavior)", ent.URL))
				break
			}
		}

		if ent.SeenSignal(knowledge.SigPublicAccess) && ent.SeenSignal(knowledge.SigAdminSurface) {
			out = append(out, fmt.Sprintf("Public admin surface: %s", ent.URL))
		}

		// JS leak evidence
		if len(ent.Content.JSLeaks) > 0 {
			out = append(out, fmt.Sprintf("Secrets/material found in JS: %s (%d leak(s))", ent.URL, len(ent.Content.JSLeaks)))
		}

	}

	// Dedup + cap to keep summary readable
	out = common.Dedup(out)
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}
