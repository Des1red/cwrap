package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"io"
	"sort"
)

type routeKey struct {
	family  string
	depth   int
	numeric bool
	num     int
}

func writeEntityDetails(w io.Writer, k *knowledge.Knowledge) {
	rw := reportWriter{w: w}

	rw.line(0, "------------------------------------------------")
	rw.line(0, "ENTITY INTELLIGENCE")
	rw.line(0, "------------------------------------------------")

	groups := entityGroupsByRoute(k)

	for _, g := range groups {
		rw.blank()
		rw.line(0, "[ENDPOINT GROUP] %s", g.Key)

		for _, ent := range g.Entities {
			if ent == nil || ent.State.IsSPAFallback {
				continue
			}

			writeEntityBlock(w, ent)
		}

		writeGroupNextSteps(w, g)
	}
}

func writeEntityBlock(w io.Writer, ent *knowledge.Entity) {
	if ent == nil || ent.State.IsSPAFallback {
		return
	}

	rw := reportWriter{w: w}

	rw.blank()
	rw.line(2, "[ENTITY] %s", ent.URL)
	rw.line(4, "Probes: %d", ent.State.ProbeCount)

	methods := sortedKeys(ent.HTTP.Methods)
	if len(methods) > 0 {
		rw.line(4, "Methods: %v", methods)
	}
	if ent.HTTP.AuthLikely {
		rw.line(4, "AuthLikely: %t", ent.HTTP.AuthLikely)
	}
	if ent.HTTP.CSRFPresent {
		rw.line(4, "CSRFPresent: %t", ent.HTTP.CSRFPresent)
	}

	if len(ent.HTTP.Tech) > 0 {
		techKeys := make([]string, 0, len(ent.HTTP.Tech))
		for k := range ent.HTTP.Tech {
			techKeys = append(techKeys, k)
		}
		sort.Strings(techKeys)

		parts := make([]string, 0, len(techKeys))
		for _, k := range techKeys {
			parts = append(parts, fmt.Sprintf("%s=%s", k, ent.HTTP.Tech[k]))
		}
		rw.line(4, "Tech: %v", parts)
	}

	if ent.Content.LooksLikeHTML {
		rw.line(4, "Content: HTML")
	} else if ent.Content.LooksLikeJSON {
		rw.line(4, "Content: JSON")
	} else if ent.Content.LooksLikeXML {
		rw.line(4, "Content: XML")
	}

	if len(ent.Content.Statuses) > 0 {
		codes := make([]int, 0, len(ent.Content.Statuses))
		for c := range ent.Content.Statuses {
			codes = append(codes, c)
		}
		sort.Ints(codes)

		parts := make([]string, 0, len(codes))
		for _, c := range codes {
			parts = append(parts, fmt.Sprintf("%d×%d", c, ent.Content.Statuses[c]))
		}
		rw.line(4, "Statuses: %s", joinSpace(parts))
	}

	if sigs := activeSignals(ent); len(sigs) > 0 {
		rw.line(4, "Signals: %v", sigs)
	}

	if ent.SessionUsed || ent.SessionIssued || len(ent.SessionCookies) > 0 {
		rw.line(4, "Session:")
		if ent.SessionUsed {
			rw.line(6, "Used: %t", ent.SessionUsed)
		}
		if ent.SessionIssued {
			rw.line(6, "Issued: %t", ent.SessionIssued)
		}
		if len(ent.SessionCookies) > 0 {
			names := make([]string, 0, len(ent.SessionCookies))
			for n := range ent.SessionCookies {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				rw.line(6, "- %s=%s", n, ent.SessionCookies[n])
			}
		}
	}

	if len(ent.Identities) > 0 {
		rw.line(4, "Identities:")
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

			tags := []string{identityKindLabel(id.Kind)}

			if id.Synthetic {
				tags = append(tags, knowledge.IdentityTagSynthetic)
			}
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

			showClaims := !(id.Synthetic && id.Rejected)
			if showClaims && id.Role != "" {
				tags = append(tags, "role="+id.Role)
			}
			if showClaims && id.UserID != "" {
				tags = append(tags, "uid="+id.UserID)
			}
			if showClaims && id.Expiry != "" {
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

			rw.line(6, "%s: %v", name, tags)

			if len(id.CookieNames) > 0 {
				rw.line(8, "cookies: %v", id.CookieNames)
			}
		}
	}

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
		rw.line(4, "Parameters:")

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

			rw.line(6, "%s: %v", name, tags)

			if len(p.ObservedChanges) > 0 {
				keys := make([]string, 0, len(p.ObservedChanges))
				for k := range p.ObservedChanges {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				rw.line(8, "changes: %v", keys)
			}

			if len(p.IdentityAccess) > 0 {
				rw.line(8, "access: %v", p.IdentityAccess)
			}
			if len(p.IdentityDenied) > 0 {
				rw.line(8, "denied: %v", p.IdentityDenied)
			}
		}
	}

	if len(ent.Content.JSFindings) > 0 || len(ent.Content.JSLeaks) > 0 {
		rw.line(4, "JS Intelligence:")

		if len(ent.Content.JSFindings) > 0 {
			keys := make([]string, 0, len(ent.Content.JSFindings))
			for k := range ent.Content.JSFindings {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rw.line(6, "%s: %d", k, ent.Content.JSFindings[k])
			}
		}

		for _, leak := range ent.Content.JSLeaks {
			rw.line(6, "[%s] %s: %s", leak.Kind, leak.Key, leak.Value)
		}
	}

	findings := deriveFindings(ent)
	if len(findings) > 0 {
		rw.line(4, "Findings:")
		for _, f := range findings {
			rw.line(6, "! %s", f)
		}
	}
}

func writeTaggedProbeLog(w io.Writer, k *knowledge.Knowledge, debug bool) {
	if !debug {
		return
	}
	rw := reportWriter{w: w}

	rw.line(0, "------------------------------------------------")
	rw.line(0, "PROBE LOG FOR TAGGED ENTITIES")
	rw.line(0, "------------------------------------------------")

	printed := false

	for _, u := range entityURLsByRoute(k) {
		ent := k.Entities[u]
		if ent == nil || ent.State.IsSPAFallback {
			continue
		}

		sigs := activeSignals(ent)
		if len(sigs) == 0 || len(ent.ProbeLog) == 0 {
			continue
		}

		rows := make([]knowledge.ProbeLogEntry, 0, len(ent.ProbeLog))
		for _, p := range ent.ProbeLog {
			if shouldPrintProbeLog(p) {
				rows = append(rows, p)
			}
		}

		if len(rows) == 0 {
			continue
		}

		sort.Slice(rows, func(i, j int) bool {
			if rows[i].URL != rows[j].URL {
				return rows[i].URL < rows[j].URL
			}
			if rows[i].Reason != rows[j].Reason {
				return rows[i].Reason < rows[j].Reason
			}
			if rows[i].IdentityKind != rows[j].IdentityKind {
				return rows[i].IdentityKind < rows[j].IdentityKind
			}
			if rows[i].Identity != rows[j].Identity {
				return rows[i].Identity < rows[j].Identity
			}
			if rows[i].Method != rows[j].Method {
				return rows[i].Method < rows[j].Method
			}
			return rows[i].Status < rows[j].Status
		})

		printed = true

		rw.blank()
		rw.line(0, "[ENTITY] %s", ent.URL)
		rw.line(2, "Signals: %v", sigs)

		for _, p := range rows {
			count := ""
			if p.Count > 1 {
				count = fmt.Sprintf(" ×%d", p.Count)
			}

			loc := ""
			if p.Location != "" {
				loc = " -> " + p.Location
			}

			reason := p.Reason
			if kind := probeIdentityKindLabel(p.IdentityKind); kind != "" {
				reason += "/" + kind
			}

			rw.line(
				2,
				"%-6s %-14s %-3d%s %s [%s]%s",
				p.Method,
				p.Identity,
				p.Status,
				count,
				p.URL,
				reason,
				loc,
			)
		}
	}

	if !printed {
		rw.line(0, "(no tagged probe log)")
	}

	rw.blank()
}

func shouldPrintProbeLog(p knowledge.ProbeLogEntry) bool {
	return p.Status != 404 && p.Status < 500
}

func writeGroupNextSteps(w io.Writer, g entityGroup) {
	rw := reportWriter{w: w}

	byStep := map[string][]string{}

	for _, ent := range g.Entities {
		if ent == nil {
			continue
		}

		for _, step := range deriveNextSteps(ent) {
			byStep[step] = append(byStep[step], ent.URL)
		}
	}

	if len(byStep) == 0 {
		return
	}

	steps := make([]string, 0, len(byStep))
	for step := range byStep {
		steps = append(steps, step)
	}
	sort.Strings(steps)

	rw.line(2, "Group Next Steps:")
	for _, step := range steps {
		urls := byStep[step]
		sort.Strings(urls)
		urls = dedup(urls)

		rw.blank()
		rw.line(4, "> %s", step)
		for _, u := range urls {
			rw.line(8, "from: %s", u)
		}
	}
}
