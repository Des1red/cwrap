package knowledge

type ParamSource int

const (
	ParamQuery    ParamSource = iota // observed in baseline URL query or discovered URL
	ParamInjected                    // added by scanner probes (e.g. _cwrap)
	ParamForm                        // discovered from HTML form
	ParamJSON                        // discovered from JSON keys
	ParamPath                        // path segment param (future)
)

const (
	ReasonParamDiscovery  = "param discovery"
	ReasonIDAdjacency     = "id adjacency"
	ReasonIDEnum          = "id enumeration"
	ReasonIdentityProbe   = "identity probe"
	ReasonMethodProbe     = "method probe"
	ReasonPathIDProbe     = "path-id-probe"
	ReasonPathIDSelfProbe = "path-id-self-probe"
	ReasonLinkProbe       = "link"
	ReasonRedirect        = "redirect"
	ReasonJSFetch         = "js-fetch"
)

const (
	ParamTagOwnershipBoundary = "OwnershipBoundary"
	ParamTagPossibleIDOR      = "PossibleIDOR"
	ParamTagSuspectIDOR       = "SuspectIDOR"
	ParamTagAuthBoundary      = "AuthBoundary"
	ParamTagIDLike            = "IDLike"
	ParamTagObjectAccess      = "ObjectAccess"
	ParamTagReflection        = "Reflection"
	ParamTagEnumerable        = "Enumerable"
	ParamTagTokenLike         = "TokenLike"
	ParamTagDebugLike         = "DebugLike"
)

func (p ParamSource) String() string {
	switch p {
	case ParamQuery:
		return "query"
	case ParamForm:
		return "form"
	case ParamJSON:
		return "json"
	case ParamPath:
		return "path"
	default:
		return "unknown"
	}
}
