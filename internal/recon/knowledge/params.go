package knowledge

type ParamSource int

const (
	ParamQuery ParamSource = iota
	ParamForm
	ParamJSON
	ParamPath
)

const (
	ReasonParamDiscovery = "param discovery"
	ReasonIDAdjacency    = "id adjacency"
	ReasonIDEnum         = "id enumeration"
	ReasonIdentityProbe  = "identity probe"
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
