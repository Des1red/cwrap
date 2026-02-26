package knowledge

type EdgeType int

const (
	EdgeDiscoveredFromHTML EdgeType = iota
	EdgeDiscoveredFromJS
	EdgeFormAction
)

type Edge struct {
	From string
	To   string
	Type EdgeType
}
