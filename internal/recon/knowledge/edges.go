package knowledge

type EdgeType int

const (
	EdgeDiscoveredFromHTML EdgeType = iota
	EdgeDiscoveredFromJS
	EdgeFormAction
)

const (
	EdgeLabelHTML = "html"
	EdgeLabelJS   = "js"
	EdgeLabelForm = "form"
	EdgeLabelEdge = "edge"
)

type Edge struct {
	From string
	To   string
	Type EdgeType
}
