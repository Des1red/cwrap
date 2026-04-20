package http

import (
	"bytes"
	"cwrap/internal/recon/jsintel"
	"cwrap/internal/recon/knowledge"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type formIntel struct {
	HasUpload     bool
	HasPassword   bool
	HasUserField  bool
	IsDestructive bool
	SubmitHints   []string
	HiddenPairs   map[string]string
}

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
							if isSensitivePath(link) {
								ent.Tag(knowledge.SigAdminSurface)
							}

							// queue discovered links as GET probes
							e.k.PushProbe(e.k.Entity(ent.URL), knowledge.Probe{
								URL:      link,
								Method:   "GET",
								Reason:   knowledge.ReasonLinkProbe,
								Priority: 60,
								Created:  time.Now(),
							})
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
				ent.AddMethod(method)
				ent.Tag(knowledge.SigHasForm)

				// Collect structural form intelligence
				fi := extractFormInputsAndIntel(e, ent, n)

				// Mark state-changing behavior
				if method == "POST" || fi.IsDestructive {
					ent.Tag(knowledge.SigStateChanging)
				}

				// HTML spec: empty action submits to current URL
				if action == "" {
					action = ent.URL
				}

				if link, ok := e.normalizeLink(ent.URL, action); ok {

					e.k.AddEdge(ent.URL, link, knowledge.EdgeFormAction)

					if isSensitivePath(link) {
						ent.Tag(knowledge.SigAdminSurface)
					}

					// ----------------------------
					// FORM EXECUTION POLICY
					// ----------------------------
					if !fi.HasUpload && !fi.IsDestructive {

						priority := 30

						// Bootstrap detection (structural only)
						isBootstrap := false
						if fi.HasPassword || containsAny(
							strings.ToLower(strings.Join(fi.SubmitHints, " ")),
							[]string{"login", "sign in", "signin", "authenticate"},
						) {
							isBootstrap = true
						}

						if isBootstrap {
							priority = 90
						} else if method == "POST" {
							priority = 60
						}

						// Respect CSRF presence detected by httpintel
						if method == "POST" && ent.HTTP.CSRFPresent && !isBootstrap {
							priority = 20
						}

						e.k.PushProbe(ent, knowledge.Probe{
							URL:      link,
							Method:   method,
							AddQuery: fi.HiddenPairs,
							Reason:   "form-action",
							Priority: priority,
							Created:  time.Now(),
						})
					}
				}

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
						// fetch the JS file so jsintel can analyze its content
						e.k.PushProbe(e.k.Entity(ent.URL), knowledge.Probe{
							URL:      link,
							Method:   "GET",
							Reason:   knowledge.ReasonJSFetch,
							Priority: 70,
							Created:  time.Now(),
						})
					}
				} else {
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

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
}
func extractFormInputsAndIntel(e *Engine, ent *knowledge.Entity, formNode *html.Node) formIntel {
	fi := formIntel{
		HiddenPairs: make(map[string]string),
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {

		if n.Type == html.ElementNode {
			switch n.Data {

			case "input":
				var name, inputType, value string

				for _, a := range n.Attr {
					switch a.Key {
					case "name":
						name = a.Val
					case "type":
						inputType = strings.ToLower(a.Val)
					case "value":
						value = a.Val
					}
				}

				// param extraction (existing behavior)
				if name != "" {
					ent.AddParam(name, knowledge.ParamForm)
					e.k.AddParam(name)
				}

				switch inputType {

				case "file":
					fi.HasUpload = true
					ent.Tag(knowledge.SigFileUpload)

				case "password":
					fi.HasPassword = true

				case "hidden":
					if name != "" {
						fi.HiddenPairs[strings.ToLower(name)] = value
					}

				case "submit":
					if value != "" {
						fi.SubmitHints = append(fi.SubmitHints, value)
					}
				}

				ln := strings.ToLower(name)
				lv := strings.ToLower(value)

				// user-ish detection
				if containsAny(ln, []string{"user", "username", "email", "login"}) {
					fi.HasUserField = true
				}

				// destructive detection
				if isDestructiveToken(ln) || isDestructiveToken(lv) {
					fi.IsDestructive = true
				}
				if ln == "action" && isDestructiveToken(lv) {
					fi.IsDestructive = true
				}

			case "button":
				btnType := ""
				for _, a := range n.Attr {
					if a.Key == "type" {
						btnType = strings.ToLower(a.Val)
					}
				}
				if btnType == "" || btnType == "submit" {
					txt := strings.TrimSpace(nodeText(n))
					if txt != "" {
						fi.SubmitHints = append(fi.SubmitHints, txt)
						if isDestructiveToken(strings.ToLower(txt)) {
							fi.IsDestructive = true
						}
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(formNode)

	return fi
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func containsAny(s string, keys []string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func isDestructiveToken(s string) bool {
	s = strings.ToLower(s)
	destructive := []string{
		"logout", "log out", "signout", "sign out",
		"delete", "remove", "destroy", "kill", "terminate",
		"deactivate", "disable", "revoke", "invalidate",
	}
	for _, k := range destructive {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
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
