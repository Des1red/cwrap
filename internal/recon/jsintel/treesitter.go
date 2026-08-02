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
	endpoints, gojaErr := extractEndpointsAST(string(source))

	if gojaErr == nil {
		dataFlowEndpoints, dataFlowErr :=
			extractEndpointsDataFlow(source)

		if dataFlowErr == nil {
			seen := make(map[string]bool)

			merged := make(
				[]JSEndpoint,
				0,
				len(endpoints)+len(dataFlowEndpoints),
			)

			for _, endpoint := range endpoints {
				appendJSEndpoint(
					&merged,
					seen,
					endpoint.Method,
					endpoint.Path,
					endpoint.Kind,
				)
			}

			for _, endpoint := range dataFlowEndpoints {
				appendJSEndpoint(
					&merged,
					seen,
					endpoint.Method,
					endpoint.Path,
					endpoint.Kind,
				)
			}

			endpoints = merged
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

	return hybridEndpointResult{
		Endpoints:    recovered,
		Scopes:       len(scopes),
		ParsedScopes: parsed,
		FailedScopes: failed,
		Recovered:    true,
	}, gojaErr
}
