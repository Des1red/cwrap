package treesitter

import (
	astp "cwrap/internal/recon/jsintel/ast"
	"cwrap/internal/recon/jsintel/common"
)

type hybridEndpointResult struct {
	Endpoints []common.JSEndpoint
	HTTPFlows []JSHTTPFlow

	Scopes       int
	ParsedScopes int
	FailedScopes int
	Recovered    bool
}

func ExtractEndpointsHybrid(
	source []byte,
) (hybridEndpointResult, error) {
	astEndpoints, gojaErr :=
		astp.ExtractEndpointsAST(string(source))

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
	groups ...[]common.JSEndpoint,
) []common.JSEndpoint {
	merged := make([]common.JSEndpoint, 0)
	seen := make(map[string]bool)

	for _, endpoints := range groups {
		for _, endpoint := range endpoints {
			common.AppendJSEndpoint(
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
