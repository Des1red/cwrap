package jsintel

import (
	"fmt"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

type dataFlowFunction struct {
	Parameters            []string
	FetchURLParam         string
	FetchMethodParam      string
	FetchURLProperty      string
	FetchMethodProperty   string
	FetchMethods          []string
	FetchStaticPath       string
	RequestURLParam       string
	RequestURLProperty    string
	RequestMethodParam    string
	RequestMethodProperty string
}
type dataFlowBinding struct {
	Target dataFlowFunction
	Values dataFlowCallValues
}

type dataFlowMutator struct {
	Parameters      []string
	FieldParameters map[string]string
}

type dataFlowInstance struct {
	ClassName string
	Fields    map[string]string
}

type dataFlowClass struct {
	ConstructorParameters []string
	FieldParameters       map[string]string
	Methods               map[string]dataFlowFunction
	Mutators              map[string]dataFlowMutator
}

type dataFlowCallValues struct {
	Scalars map[string]string
	Objects map[string]map[string]string
}

func newDataFlowCallValues() dataFlowCallValues {
	return dataFlowCallValues{
		Scalars: make(map[string]string),
		Objects: make(map[string]map[string]string),
	}
}

func mergeDataFlowCallValues(
	base dataFlowCallValues,
	extra dataFlowCallValues,
) dataFlowCallValues {
	result := newDataFlowCallValues()

	for name, value := range base.Scalars {
		result.Scalars[name] = value
	}

	for name, properties := range base.Objects {
		copied := make(map[string]string)

		for property, value := range properties {
			copied[property] = value
		}

		result.Objects[name] = copied
	}

	for name, value := range extra.Scalars {
		result.Scalars[name] = value
	}

	for name, properties := range extra.Objects {
		if result.Objects[name] == nil {
			result.Objects[name] = make(map[string]string)
		}

		for property, value := range properties {
			result.Objects[name][property] = value
		}
	}

	return result
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

	bindings := findDataFlowBindings(
		root,
		source,
		stringValues,
	)
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

		binding, exists := bindings[functionName]
		if !exists {
			return
		}

		callValues := resolveDataFlowCallValues(
			binding.Target,
			argumentsNode,
			source,
			stringValues,
		)

		values := mergeDataFlowCallValues(
			binding.Values,
			callValues,
		)

		methods := resolveDataFlowMethods(
			binding.Target,
			values,
		)

		path, kind, ok := resolveDataFlowPath(
			binding.Target,
			values,
		)
		if !ok {
			return
		}

		for _, method := range methods {
			appendJSEndpoint(
				&endpoints,
				seen,
				method,
				path,
				kind,
			)
		}
	})

	return endpoints, nil
}
