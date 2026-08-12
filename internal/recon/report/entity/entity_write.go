package entity

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"cwrap/internal/recon/report/derive"
	"cwrap/internal/recon/report/js"
	"fmt"
	"io"
	"sort"
	"strings"
)

type routeKey struct {
	family  string
	depth   int
	numeric bool
	num     int
}

func WriteEntityDetails(w io.Writer, k *knowledge.Knowledge) {
	rw := common.ReportWriter{W: w}

	rw.Line(0, "------------------------------------------------")
	rw.Line(0, "ENTITY INTELLIGENCE")
	rw.Line(0, "------------------------------------------------")

	groups := entityGroupsByRoute(k)

	for _, g := range groups {
		rw.Blank()
		rw.Line(0, "[ENDPOINT GROUP] %s", g.Key)

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

	rw := common.ReportWriter{W: w}

	// keyWidth aligns the vitals block's key column; "MissingSecurityHeaders:"
	// (23 chars) is the longest label, so 24 leaves a one-space gutter.
	const keyWidth = 24

	rw.Blank()
	rw.Line(2, "[ENTITY] %s", ent.URL)
	rw.KV(4, keyWidth, "Probes:", "%d", ent.State.ProbeCount)

	methods := sortedKeys(ent.HTTP.Methods)
	if len(methods) > 0 {
		rw.KV(4, keyWidth, "Methods:", "%s", common.JoinComma(methods))
	}
	if ent.HTTP.AuthLikely {
		rw.KV(4, keyWidth, "AuthLikely:", "%t", ent.HTTP.AuthLikely)
	}
	if ent.HTTP.CSRFPresent {
		rw.KV(4, keyWidth, "CSRFPresent:", "%t", ent.HTTP.CSRFPresent)
	}
	if ent.HTTP.AuthScheme != "" {
		rw.KV(4, keyWidth, "AuthScheme:", "%s", ent.HTTP.AuthScheme)
	}
	if ent.HTTP.CORSPermissive {
		rw.KV(4, keyWidth, "CORSOrigin:", "%s", ent.HTTP.CORSOrigin)
	}
	if ent.HTTP.FrameAncestors != "" {
		rw.KV(4, keyWidth, "FrameAncestors:", "%s", ent.HTTP.FrameAncestors)
	}
	if len(ent.HTTP.MissingSecurityHeaders) > 0 {
		rw.KV(4, keyWidth, "MissingSecurityHeaders:", "%s", common.JoinComma(ent.HTTP.MissingSecurityHeaders))
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
		rw.KV(4, keyWidth, "Tech:", "%s", common.JoinComma(parts))
	}

	if ent.Content.LooksLikeHTML {
		rw.KV(4, keyWidth, "Content:", "%s", "HTML")
	} else if ent.Content.LooksLikeJSON {
		rw.KV(4, keyWidth, "Content:", "%s", "JSON")
	} else if ent.Content.LooksLikeXML {
		rw.KV(4, keyWidth, "Content:", "%s", "XML")
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
		rw.KV(4, keyWidth, "Statuses:", "%s", common.JoinSpace(parts))
	}

	sigs := activeSignals(ent)
	if len(sigs) > 0 {
		rw.KV(4, keyWidth, "Signals:", "%s", common.JoinComma(sigs))
	}

	if ent.SessionUsed || ent.SessionIssued || len(ent.SessionCookies) > 0 {
		rw.Blank()
		rw.Line(4, "Session:")
		if ent.SessionUsed {
			rw.Line(6, "Used: %t", ent.SessionUsed)
		}
		if ent.SessionIssued {
			rw.Line(6, "Issued: %t", ent.SessionIssued)
		}
		if len(ent.SessionCookies) > 0 {
			names := make([]string, 0, len(ent.SessionCookies))
			for n := range ent.SessionCookies {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				rw.Line(6, "- %s=%s", n, ent.SessionCookies[n])
			}
		}
	}

	if len(ent.Identities) > 0 {
		rw.Blank()
		rw.Line(4, "Identities:")
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

			rw.Line(6, "%s: %s", name, common.JoinComma(tags))

			if len(id.CookieNames) > 0 {
				rw.Line(8, "cookies: %s", common.JoinComma(id.CookieNames))
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
		rw.Blank()
		rw.Line(4, "Parameters:")

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

			rw.Line(6, "%s: %s", name, common.JoinComma(tags))

			if len(p.ObservedChanges) > 0 {
				keys := make([]string, 0, len(p.ObservedChanges))
				for k := range p.ObservedChanges {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				rw.Line(8, "changes: %s", common.JoinComma(keys))
			}

			if len(p.IdentityAccess) > 0 {
				rw.Line(8, "access: %v", p.IdentityAccess)
			}
			if len(p.IdentityDenied) > 0 {
				rw.Line(8, "denied: %v", p.IdentityDenied)
			}
		}
	}

	jsFindingKeys := js.ReportableJSFindingKeys(ent)

	if len(jsFindingKeys) > 0 ||
		len(ent.Content.JSLeaks) > 0 ||
		len(ent.Content.JSHTTPFlows) > 0 {

		rw.Blank()
		rw.Line(4, "JS Intelligence:")

		if len(jsFindingKeys) > 0 {
			rw.Line(6, "Signals:")

			for _, key := range jsFindingKeys {
				rw.Line(
					8,
					"%s: %d",
					key,
					ent.Content.JSFindings[key],
				)
			}
		}

		if len(ent.Content.JSLeaks) > 0 {
			rw.Blank()
			rw.Line(6, "JS Leaks:")

			for _, leak := range ent.Content.JSLeaks {
				rw.Line(
					8,
					"[%s] %s: %s",
					leak.Kind,
					leak.Key,
					leak.Value,
				)
			}
		}

		if len(ent.Content.JSHTTPFlows) > 0 {
			rw.Blank()
			rw.Line(6, "Dynamic HTTP Flows:")

			flows := append(
				[]knowledge.JSHTTPFlow(nil),
				ent.Content.JSHTTPFlows...,
			)

			sort.SliceStable(flows, func(i, j int) bool {
				if flows[i].Function != flows[j].Function {
					return flows[i].Function < flows[j].Function
				}

				if flows[i].Sink != flows[j].Sink {
					return flows[i].Sink < flows[j].Sink
				}

				if flows[i].URLSource != flows[j].URLSource {
					return flows[i].URLSource < flows[j].URLSource
				}

				return flows[i].MethodSource <
					flows[j].MethodSource
			})

			for _, flow := range flows {
				function := strings.TrimSpace(flow.Function)
				if function == "" {
					function = "(anonymous)"
				}

				sink := strings.TrimSpace(flow.Sink)
				if sink == "" {
					sink = "unknown HTTP sink"
				}

				confidence := strings.TrimSpace(
					flow.Confidence,
				)
				if confidence == "" {
					confidence = "unknown"
				}

				rw.Line(
					8,
					"- %s -> %s [%s confidence]",
					function,
					sink,
					confidence,
				)

				if flow.ResolvedURL != "" {
					rw.Line(
						10,
						"URL: %s [resolved]",
						flow.ResolvedURL,
					)
				} else {
					urlSource := strings.TrimSpace(
						flow.URLSource,
					)
					if urlSource == "" {
						urlSource = "unknown"
					}

					rw.Line(
						10,
						"URL source: %s [dynamic]",
						urlSource,
					)
				}

				if flow.ResolvedMethod != "" {
					rw.Line(
						10,
						"Method: %s [resolved]",
						flow.ResolvedMethod,
					)
				} else {
					methodSource := strings.TrimSpace(
						flow.MethodSource,
					)
					if methodSource == "" {
						methodSource = "unknown"
					}

					rw.Line(
						10,
						"Method source: %s [dynamic]",
						methodSource,
					)
				}
			}
		}
	}

	findings := derive.DeriveFindings(ent)
	if len(findings) > 0 {
		rw.Blank()
		rw.Line(4, "Findings:")
		for _, f := range findings {
			rw.Line(6, "! %s", f)
		}
	}
}
