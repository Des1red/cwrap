package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
)

// Interpreter lets behavior reason about responses
// without knowing the data format (json/html/etc).
type Interpreter interface {

	// Learn lets the format layer extract intelligence
	Learn(url string, resp *http.Response, body []byte)

	// Canonicalize removes value noise so behavior can compare structure
	Canonicalize(body []byte, param string) ([]byte, error)

	// ClassifyParam lets the format layer label parameters
	ClassifyParam(ent *knowledge.Entity, name string)
}
