package jsintel

import (
	"fmt"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

type dataFlowFunction struct {
	Parameters          []string
	FetchURLParam       string
	FetchMethodParam    string
	FetchURLProperty    string
	FetchMethodProperty string
}

type dataFlowCallValues struct {
	Scalars map[string]string
	Objects map[string]map[string]string
}

func extractEndpointsDataFlow(
	source []byte,
) ([]JSEndpoint, error) {
	tree, err := parseJavaScriptTree(source)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		return nil, fmt.Errorf("tree-sitter returned nil root node")
	}
	stringValues := findStringVariables(root, source)

	functions := findNamedDataFlowFunctions(root, source)

	endpoints := make([]JSEndpoint, 0)
	seen := make(map[string]bool)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "call_expression" {
			return
		}

		functionNode := node.ChildByFieldName("function")
		argumentsNode := node.ChildByFieldName("arguments")

		if functionNode == nil || argumentsNode == nil {
			return
		}

		functionName := strings.TrimSpace(
			functionNode.Utf8Text(source),
		)

		target, exists := functions[functionName]
		if !exists {
			return
		}

		callValues := resolveDataFlowCallValues(
			target,
			argumentsNode,
			source,
			stringValues,
		)

		method := resolveDataFlowMethod(target, callValues)

		path, kind, ok := resolveDataFlowPath(target, callValues)
		if !ok {
			return
		}

		appendJSEndpoint(
			&endpoints,
			seen,
			method,
			path,
			kind,
		)
	})

	return endpoints, nil
}
