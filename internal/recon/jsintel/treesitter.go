package jsintel

type hybridEndpointResult struct {
	Endpoints    []JSEndpoint
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

	dataFlowEndpoints, dataFlowErr :=
		extractEndpointsDataFlow(source)

	if gojaErr == nil {
		endpoints := astEndpoints

		if dataFlowErr == nil {
			endpoints = mergeJSEndpoints(
				astEndpoints,
				dataFlowEndpoints,
			)
		}

		return hybridEndpointResult{
			Endpoints: endpoints,
		}, nil
	}

	scopes, treeErr := findHTTPCallScopes(source)
	if treeErr != nil {
		return hybridEndpointResult{}, treeErr
	}

	recovered, parsed, failed :=
		extractEndpointsFromTreeScopes(scopes)

	if dataFlowErr == nil {
		recovered = mergeJSEndpoints(
			recovered,
			dataFlowEndpoints,
		)
	}

	return hybridEndpointResult{
		Endpoints:    recovered,
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
