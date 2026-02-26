package http

import (
	"bytes"
	"cwrap/internal/recon/jsintel"
	"cwrap/internal/recon/knowledge"
	"strings"

	"golang.org/x/net/html"
)

func (e *Engine) extractHTML(ent *knowledge.Entity, body []byte) {

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return
	}

	var walk func(*html.Node)

	walk = func(n *html.Node) {

		if n.Type == html.ElementNode {

			switch n.Data {

			// ----------------------------
			// LINKS
			// ----------------------------
			case "a":
				for _, a := range n.Attr {
					if a.Key == "href" && a.Val != "" {
						if link, ok := e.normalizeLink(ent.URL, a.Val); ok {

							e.k.AddEdge(ent.URL, link, knowledge.EdgeDiscoveredFromHTML)

							// surface tagging
							if isSensitivePath(link) {
								ent.Tag(knowledge.SigAdminSurface)
							}
						}
					}
				}

			// ----------------------------
			// FORMS
			// ----------------------------
			case "form":

				method := "GET"
				action := ""

				for _, a := range n.Attr {
					switch a.Key {
					case "method":
						method = strings.ToUpper(a.Val)
					case "action":
						action = a.Val
					}
				}

				if method == "POST" {
					ent.Tag(knowledge.SigStateChanging)
				}

				if link, ok := e.normalizeLink(ent.URL, action); ok {
					e.k.AddEdge(ent.URL, link, knowledge.EdgeFormAction)

					if isSensitivePath(link) {
						ent.Tag(knowledge.SigAdminSurface)
					}
				}

				ent.Tag(knowledge.SigHasForm)

				// Extract form inputs
				extractFormInputs(e, ent, n)

			// ----------------------------
			// SCRIPT
			// ----------------------------
			case "script":

				var src string
				for _, a := range n.Attr {
					if a.Key == "src" {
						src = a.Val
					}
				}

				if src != "" {
					if link, ok := e.normalizeLink(ent.URL, src); ok {
						e.k.AddEdge(ent.URL, link, knowledge.EdgeDiscoveredFromJS)
					}
				} else {
					// inline JS (collect full text content)
					var code strings.Builder
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.TextNode {
							code.WriteString(c.Data)
						}
					}

					if code.Len() > 0 {
						jsintel.Learn(ent, ent.URL+"#inline", []byte(code.String()))
					}
				}
			}
		}

		// ALWAYS recurse
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
}

func extractFormInputs(e *Engine, ent *knowledge.Entity, formNode *html.Node) {

	for c := formNode.FirstChild; c != nil; c = c.NextSibling {

		if c.Type != html.ElementNode {
			continue
		}

		if c.Data == "input" {

			var name, inputType string

			for _, a := range c.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "type":
					inputType = strings.ToLower(a.Val)
				}
			}

			if name != "" {
				ent.AddParam(name, knowledge.ParamForm)
				e.k.AddParam(name)
			}

			if inputType == "file" {
				ent.Tag(knowledge.SigFileUpload)
			}
		}
	}
}

func isSensitivePath(link string) bool {

	l := strings.ToLower(link)

	keywords := []string{
		"/admin",
		"/internal",
		"/private",
		"/debug",
		"/config",
		"/upload",
		"/backup",
		"/swagger",
		"/graphql",
	}

	for _, k := range keywords {
		if strings.Contains(l, k) {
			return true
		}
	}

	return false
}
