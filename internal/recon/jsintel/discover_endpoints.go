package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"strings"
)

func discoverEndpoints(
	ent *knowledge.Entity,
	sourceURL string,
	source string,
) []JSEndpoint {
	seen := make(map[string]bool)
	endpoints := make([]JSEndpoint, 0)
	endpointCount := 0

	result, astErr := extractEndpointsHybrid([]byte(source))

	if astErr != nil {
		ent.Content.JSFindings["ast_parse_error"]++

		if result.Recovered {
			ent.Content.JSFindings["ast_recovery_run"]++
			ent.Content.JSFindings["ast_recovery_scopes"] += result.Scopes
			ent.Content.JSFindings["ast_recovery_parsed"] += result.ParsedScopes
			ent.Content.JSFindings["ast_recovery_failed"] += result.FailedScopes
		}

		if len(result.Endpoints) > 0 {
			ent.Content.JSFindings["ast_recovered"]++
		}
	} else {
		ent.Content.JSFindings["ast_parsed"]++
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
		ent.Content.JSFindings["http_flow"] += flowCount
	}

	for _, endpoint := range result.Endpoints {

		if addJSEndpoint(
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

	for _, match := range reFetch.FindAllStringSubmatch(source, -1) {
		if addJSEndpoint(
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

	for _, match := range reAxios.FindAllStringSubmatch(source, -1) {
		if addJSEndpoint(
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

	for _, match := range reXHR.FindAllStringSubmatch(source, -1) {
		if addJSEndpoint(
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

	for _, match := range rePathLiteral.FindAllStringSubmatch(source, -1) {
		if addJSEndpoint(
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
		ent.Content.JSFindings["endpoint"] += endpointCount
	}

	return endpoints
}
