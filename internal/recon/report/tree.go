package report

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

type treeNode struct {
	Name     string
	URL      string
	IsEntity bool
	Children map[string]*treeNode
}

func writeDiscoveryTree(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "DISCOVERY TREE")
	fmt.Fprintln(w, "------------------------------------------------")

	type child struct {
		to    string
		etype knowledge.EdgeType
	}
	adj := make(map[string][]child)
	for u := range k.Entities {
		if _, ok := adj[u]; !ok {
			adj[u] = nil
		}
	}
	for _, e := range k.Edges {
		adj[e.From] = append(adj[e.From], child{to: e.To, etype: e.Type})
		if _, ok := adj[e.To]; !ok {
			adj[e.To] = nil
		}
	}
	for from := range adj {
		seen := map[string]bool{}
		deduped := make([]child, 0, len(adj[from]))
		for _, c := range adj[from] {
			key := c.to + "|" + edgeTypeLabel(c.etype)
			if !seen[key] {
				seen[key] = true
				deduped = append(deduped, c)
			}
		}
		adj[from] = deduped
	}

	root := ""
	if k.Target != "" {
		if _, ok := k.Entities[k.Target]; ok {
			root = k.Target
		}
	}
	if root == "" {
		urls := common.SortedEntityURLs(k)
		if len(urls) > 0 {
			root = urls[0]
		}
	}
	if root == "" {
		fmt.Fprintln(w, "(no entities)")
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w, root)
	visited := map[string]bool{root: true}
	var walk func(node string, prefix string)
	walk = func(node string, prefix string) {
		children := adj[node]
		for i, c := range children {
			last := i == len(children)-1
			branch := "├── "
			nextPrefix := prefix + "│   "
			if last {
				branch = "└── "
				nextPrefix = prefix + "    "
			}
			line := fmt.Sprintf("%s%s%s", prefix, branch, c.to)
			if tag := edgeTypeLabel(c.etype); tag != "" {
				line += "  [" + tag + "]"
			}
			if visited[c.to] {
				line += "  (seen)"
				fmt.Fprintln(w, line)
				continue
			}
			fmt.Fprintln(w, line)
			visited[c.to] = true
			walk(c.to, nextPrefix)
		}
	}
	walk(root, "")
	fmt.Fprintln(w)
}

func edgeTypeLabel(t knowledge.EdgeType) string {
	switch t {
	case knowledge.EdgeDiscoveredFromHTML:
		return knowledge.EdgeLabelHTML
	case knowledge.EdgeDiscoveredFromJS:
		return knowledge.EdgeLabelJS
	case knowledge.EdgeFormAction:
		return knowledge.EdgeLabelForm
	default:
		return knowledge.EdgeLabelEdge
	}
}

func buildPathTree(k *knowledge.Knowledge) *treeNode {
	root := &treeNode{
		Name:     k.Target,
		URL:      k.Target,
		IsEntity: true,
		Children: map[string]*treeNode{},
	}

	for _, rawURL := range common.SortedEntityURLs(k) {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) == 1 && parts[0] == "" {
			root.IsEntity = true
			continue
		}

		cur := root
		base := u.Scheme + "://" + u.Host

		path := ""
		for _, part := range parts {
			if part == "" {
				continue
			}

			path += "/" + part
			childURL := base + path

			if cur.Children == nil {
				cur.Children = map[string]*treeNode{}
			}

			child := cur.Children[part]
			if child == nil {
				child = &treeNode{
					Name:     part,
					URL:      childURL,
					Children: map[string]*treeNode{},
				}
				cur.Children[part] = child
			}

			cur = child
		}

		cur.IsEntity = true
		cur.URL = rawURL
	}

	return root
}

func printPathTree(w io.Writer, node *treeNode, prefix string) {
	keys := make([]string, 0, len(node.Children))
	for k := range node.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, key := range keys {
		child := node.Children[key]

		last := i == len(keys)-1
		branch := "├── "
		nextPrefix := prefix + "│   "
		if last {
			branch = "└── "
			nextPrefix = prefix + "    "
		}

		label := child.Name
		if child.IsEntity {
			label += "  [entity]"
		}

		fmt.Fprintln(w, prefix+branch+label)
		printPathTree(w, child, nextPrefix)
	}
}

func writeRouteTree(w io.Writer, k *knowledge.Knowledge) {
	fmt.Fprintln(w, "------------------------------------------------")
	fmt.Fprintln(w, "ROUTE TREE")
	fmt.Fprintln(w, "------------------------------------------------")

	root := buildPathTree(k)
	if root == nil {
		fmt.Fprintln(w, "(no routes)")
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w, root.Name)
	printPathTree(w, root, "")
	fmt.Fprintln(w)
}
