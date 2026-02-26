package http

import (
	"bytes"
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

			case "a":
				for _, a := range n.Attr {
					if a.Key == "href" && a.Val != "" {
						if link, ok := e.normalizeLink(ent.URL, a.Val); ok {
							e.k.AddEdge(ent.URL, link, knowledge.EdgeDiscoveredFromHTML)
						}
					}
				}

			case "form":
				method := "GET"
				action := ""

				for _, a := range n.Attr {
					if a.Key == "method" {
						method = strings.ToUpper(a.Val)
					}
					if a.Key == "action" {
						action = a.Val
					}
				}

				if method == "POST" {
					ent.Tag(knowledge.SigStateChanging)
				}

				if link, ok := e.normalizeLink(ent.URL, action); ok {
					e.k.AddEdge(ent.URL, link, knowledge.EdgeFormAction)
				}

				ent.Tag(knowledge.SigHasForm)

			case "script":
				for _, a := range n.Attr {
					if a.Key == "src" && a.Val != "" {
						if link, ok := e.normalizeLink(ent.URL, a.Val); ok {
							e.k.AddEdge(ent.URL, link, knowledge.EdgeLinkedScript)
						}
					}
				}
			}

			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}

		walk(doc)
	}
}
