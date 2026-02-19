package knowledge

type EdgeType int

const (
	EdgeDiscoveredFromHTML EdgeType = iota
	EdgeDiscoveredFromJS
	EdgeDiscoveredFromAPI
	EdgeRedirect
	EdgeFormAction
	EdgeNavigation
)

type Edge struct {
	From string
	To   string
	Type EdgeType
}
