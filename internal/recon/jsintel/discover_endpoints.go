package jsintel

import (
	"cwrap/internal/recon/jsintel/common"
	"cwrap/internal/recon/jsintel/treesitter"
	"cwrap/internal/recon/knowledge"
	"strings"
)

func discoverEndpoints(
	ent *knowledge.Entity,
	sourceURL string,
	source string,
) []common.JSEndpoint {
	seen := make(map[string]bool)
	endpoints := make([]common.JSEndpoint, 0)
	endpointCount := 0

	result, astErr := treesitter.ExtractEndpointsHybrid([]byte(source))

	if astErr != nil {
		ent.Content.JSFindings[knowledge.JSFindingASTParseError]++

		if result.Recovered {
			ent.Content.JSFindings[knowledge.JSFindingASTRecoveryRun]++
			ent.Content.JSFindings[knowledge.JSFindingASTRecoveryScopes] += result.Scopes
			ent.Content.JSFindings[knowledge.JSFindingASTRecoveryParsed] += result.ParsedScopes
			ent.Content.JSFindings[knowledge.JSFindingASTRecoveryFailed] += result.FailedScopes
		}

		if len(result.Endpoints) > 0 {
			ent.Content.JSFindings[knowledge.JSFindingASTRecovered]++
		}
	} else {
		ent.Content.JSFindings[knowledge.JSFindingASTParsed]++
	}

	flowCount := 0

	for _, flow := range result.HTTPFlows {
		added := ent.AddJSHTTPFlow(
			knowledge.JSHTTPFlow{
				Source:         sourceURL,
				Function:       flow.Function,
				Sink:           flow.Sink,
				URLSource:      flow.URLSource,
				MethodSource:   flow.MethodSource,
				ResolvedURL:    flow.ResolvedURL,
				ResolvedMethod: flow.ResolvedMethod,
				DynamicURL:     flow.DynamicURL,
				DynamicMethod:  flow.DynamicMethod,
				Confidence:     flow.Confidence,
			},
		)

		if added {
			flowCount++
		}
	}

	if flowCount > 0 {
		ent.Content.JSFindings[knowledge.JSFindingHTTPFlow] += flowCount
	}

	for _, endpoint := range result.Endpoints {

		if common.AddJSEndpoint(
			ent,
			&endpoints,
			seen,
			endpoint.Method,
			endpoint.Path,
			endpoint.Kind,
		) {
			endpointCount++
		}
	}

	for _, match := range common.ReFetch.FindAllStringSubmatch(source, -1) {
		if common.AddJSEndpoint(
			ent,
			&endpoints,
			seen,
			"GET",
			match[1],
			"fetch",
		) {
			endpointCount++
		}
	}

	for _, match := range common.ReAxios.FindAllStringSubmatch(source, -1) {
		if common.AddJSEndpoint(
			ent,
			&endpoints,
			seen,
			strings.ToUpper(match[1]),
			match[2],
			"axios",
		) {
			endpointCount++
		}
	}

	for _, match := range common.ReXHR.FindAllStringSubmatch(source, -1) {
		if common.AddJSEndpoint(
			ent,
			&endpoints,
			seen,
			strings.ToUpper(match[1]),
			match[2],
			"xhr",
		) {
			endpointCount++
		}
	}

	for _, match := range common.RePathLiteral.FindAllStringSubmatch(source, -1) {
		if common.AddJSEndpoint(
			ent,
			&endpoints,
			seen,
			"GET",
			match[1],
			"literal",
		) {
			endpointCount++
		}
	}

	if endpointCount > 0 {
		ent.Content.JSFindings[knowledge.JSFindingEndpoint] += endpointCount
	}

	return endpoints
}
