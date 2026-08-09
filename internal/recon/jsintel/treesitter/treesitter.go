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

// withDataFlowMerge merges base with the dataflow pass's endpoints and
// surfaces its HTTP flows, but only if the dataflow pass itself
// succeeded — on dataFlowErr it returns base untouched and no flows,
// same as the two inlined blocks it replaces.
func withDataFlowMerge(
	base []common.JSEndpoint,
	dataFlowResult dataFlowExtractionResult,
	dataFlowErr error,
) ([]common.JSEndpoint, []JSHTTPFlow) {
	if dataFlowErr != nil {
		return base, nil
	}

	return mergeJSEndpoints(base, dataFlowResult.Endpoints),
		dataFlowResult.HTTPFlows
}

func ExtractEndpointsHybrid(
	source []byte,
) (hybridEndpointResult, error) {
	astEndpoints, gojaErr :=
		astp.ExtractEndpointsAST(string(source))

	dataFlowResult, dataFlowErr :=
		extractEndpointsDataFlow(source)

	if gojaErr == nil {
		endpoints, flows := withDataFlowMerge(
			astEndpoints,
			dataFlowResult,
			dataFlowErr,
		)

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

	recovered, flows := withDataFlowMerge(
		recovered,
		dataFlowResult,
		dataFlowErr,
	)

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
