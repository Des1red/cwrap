package jsintel

import (
	"fmt"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

func parseJavaScriptTree(source []byte) (*tree_sitter.Tree, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()

	language := tree_sitter.NewLanguage(
		tree_sitter_javascript.Language(),
	)

	if err := parser.SetLanguage(language); err != nil {
		return nil, fmt.Errorf("set JavaScript grammar: %w", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, fmt.Errorf("tree-sitter returned nil tree")
	}

	return tree, nil
}

type javaScriptScope struct {
	Kind   string
	Start  uint
	End    uint
	Source string
}

func walkTree(
	node *tree_sitter.Node,
	visit func(*tree_sitter.Node),
) {
	if node == nil {
		return
	}

	visit(node)

	for index := uint(0); index < node.NamedChildCount(); index++ {
		child := node.NamedChild(index)
		if child == nil {
			continue
		}

		walkTree(child, visit)
	}
}

func isHTTPCallNode(
	call *tree_sitter.Node,
	source []byte,
	axiosClients map[string]bool,
) bool {
	if call == nil {
		return false
	}

	function := call.ChildByFieldName("function")
	if function == nil {
		return false
	}

	name := strings.TrimSpace(function.Utf8Text(source))
	lower := strings.ToLower(name)

	if lower == "fetch" || lower == "axios" {
		return true
	}

	if strings.HasPrefix(lower, "axios.") {
		switch strings.TrimPrefix(lower, "axios.") {
		case "get", "post", "put", "delete", "patch", "options", "head":
			return true
		}
	}

	if function.Kind() == "member_expression" {
		object := function.ChildByFieldName("object")
		property := function.ChildByFieldName("property")

		if object != nil && property != nil {
			clientName := strings.TrimSpace(object.Utf8Text(source))
			method := strings.ToLower(
				strings.TrimSpace(property.Utf8Text(source)),
			)

			if axiosClients[clientName] {
				switch method {
				case "get", "post", "put", "delete",
					"patch", "options", "head":
					return true
				}
			}
		}
	}

	if strings.HasSuffix(lower, ".open") {
		return isXHRLikeOpenCall(call, source)
	}

	return false
}

func isXHRLikeOpenCall(
	call *tree_sitter.Node,
	source []byte,
) bool {
	arguments := call.ChildByFieldName("arguments")
	if arguments == nil || arguments.NamedChildCount() < 2 {
		return false
	}

	methodNode := arguments.NamedChild(0)
	if methodNode == nil {
		return false
	}

	method := strings.TrimSpace(methodNode.Utf8Text(source))
	method = strings.Trim(method, `"'`)

	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
		return true
	default:
		return false
	}
}
func nearestJavaScriptScope(
	node *tree_sitter.Node,
) *tree_sitter.Node {
	for current := node; current != nil; current = current.Parent() {
		switch current.Kind() {
		case "function_declaration",
			"function_expression",
			"arrow_function":
			return current
		}
	}

	return nil
}

func extractEndpointsFromTreeScopes(
	scopes []javaScriptScope,
) ([]JSEndpoint, int, int) {
	endpoints := make([]JSEndpoint, 0)
	seen := make(map[string]bool)
	parsedScopes := 0
	failedScopes := 0

	for _, scope := range scopes {
		scopeSource := prepareScopeForGoja(scope)

		resolved, parseErr := parseEndpointProgram(scopeSource)
		if parseErr != nil {
			failedScopes++
			continue
		}

		parsedScopes++

		for _, endpoint := range resolved {
			appendJSEndpoint(
				&endpoints,
				seen,
				endpoint.Method,
				endpoint.Path,
				endpoint.Kind,
			)
		}
	}

	return endpoints, parsedScopes, failedScopes
}

func prepareScopeForGoja(scope javaScriptScope) string {
	switch scope.Kind {
	case "function_expression",
		"arrow_function":
		return "(" + scope.Source + ");"

	default:
		return scope.Source
	}
}

func treeStringLiteral(
	node *tree_sitter.Node,
	source []byte,
) (string, bool) {
	if node == nil || node.Kind() != "string" {
		return "", false
	}

	raw := strings.TrimSpace(node.Utf8Text(source))
	if len(raw) < 2 {
		return "", false
	}

	quote := raw[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	if raw[len(raw)-1] != quote {
		return "", false
	}

	return raw[1 : len(raw)-1], true
}
