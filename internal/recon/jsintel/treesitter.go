package jsintel

type hybridEndpointResult struct {
	Endpoints []JSEndpoint
	HTTPFlows []JSHTTPFlow

	Scopes       int
	ParsedScopes int
	FailedScopes int
	Recovered    bool
}

func extractEndpointsHybrid(
	source []byte,
) (hybridEndpointResult, error) {
	astEndpoints, gojaErr :=
		extractEndpointsAST(string(source))

	dataFlowResult, dataFlowErr :=
		extractEndpointsDataFlow(source)

	if gojaErr == nil {
		endpoints := astEndpoints
		var flows []JSHTTPFlow

		if dataFlowErr == nil {
			endpoints = mergeJSEndpoints(
				astEndpoints,
				dataFlowResult.Endpoints,
			)

			flows = dataFlowResult.HTTPFlows
		}

		return hybridEndpointResult{
			Endpoints: endpoints,
			HTTPFlows: flows,
		}, nil
	}

	scopes, treeErr := findHTTPCallScopes(source)
	if treeErr != nil {
		return hybridEndpointResult{}, treeErr
	}

	recovered, parsed, failed :=
		extractEndpointsFromTreeScopes(scopes)

	var flows []JSHTTPFlow

	if dataFlowErr == nil {
		recovered = mergeJSEndpoints(
			recovered,
			dataFlowResult.Endpoints,
		)

		flows = dataFlowResult.HTTPFlows
	}

	return hybridEndpointResult{
		Endpoints:    recovered,
		HTTPFlows:    flows,
		Scopes:       len(scopes),
		ParsedScopes: parsed,
		FailedScopes: failed,
		Recovered:    true,
	}, gojaErr
}

func mergeJSEndpoints(
	groups ...[]JSEndpoint,
) []JSEndpoint {
	merged := make([]JSEndpoint, 0)
	seen := make(map[string]bool)

	for _, endpoints := range groups {
		for _, endpoint := range endpoints {
			appendJSEndpoint(
				&merged,
				seen,
				endpoint.Method,
				endpoint.Path,
				endpoint.Kind,
			)
		}
	}

	return merged
}
