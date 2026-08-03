package jsintel

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

func resolveDataFlowMethods(
	target dataFlowFunction,
	values dataFlowCallValues,
) []string {
	if len(target.FetchMethods) > 0 {
		return target.FetchMethods
	}

	if target.RequestMethodProperty != "" {
		properties := values.Objects[target.RequestMethodParam]

		if resolved, exists :=
			properties[target.RequestMethodProperty]; exists {
			return []string{
				strings.ToUpper(resolved),
			}
		}
	}

	if target.FetchMethodProperty != "" {
		properties := values.Objects[target.FetchMethodParam]

		if resolved, exists :=
			properties[target.FetchMethodProperty]; exists {
			return []string{strings.ToUpper(resolved)}
		}
	}

	if target.FetchMethodParam != "" {
		if resolved, exists :=
			values.Scalars[target.FetchMethodParam]; exists {
			return []string{strings.ToUpper(resolved)}
		}
	}

	return []string{"GET"}
}

func resolveDataFlowPath(
	target dataFlowFunction,
	values dataFlowCallValues,
) (string, string, bool) {
	if target.FetchStaticPath != "" {
		return target.FetchStaticPath,
			"fetch-request-dataflow-ast",
			true
	}

	if target.RequestURLProperty != "" {
		properties := values.Objects[target.RequestURLParam]

		path, exists := properties[target.RequestURLProperty]

		return path,
			"fetch-request-object-dataflow-ast",
			exists
	}

	if target.FetchURLProperty != "" {
		properties := values.Objects[target.FetchURLParam]

		path, exists := properties[target.FetchURLProperty]
		return path, "fetch-object-dataflow-ast", exists
	}

	if target.FetchURLParam != "" {
		path, exists := values.Scalars[target.FetchURLParam]
		return path, "fetch-dataflow-ast", exists
	}

	return "", "", false
}

func resolveDataFlowCallValues(
	target dataFlowFunction,
	arguments *tree_sitter.Node,
	source []byte,
	stringValues map[string]string,
) dataFlowCallValues {
	result := newDataFlowCallValues()

	if arguments == nil {
		return result
	}

	count := arguments.NamedChildCount()
	parameterCount := uint(len(target.Parameters))

	if parameterCount < count {
		count = parameterCount
	}

	for index := uint(0); index < count; index++ {
		argument := arguments.NamedChild(index)
		if argument == nil {
			continue
		}

		parameter := target.Parameters[index]

		if value, ok := resolveDataFlowArgument(
			argument,
			source,
			stringValues,
		); ok {
			result.Scalars[parameter] = value
		}

		objectValues := resolveObjectStringProperties(
			argument,
			source,
		)

		if len(objectValues) > 0 {
			result.Objects[parameter] = objectValues
		}
	}

	return result
}

func resolveDataFlowArgument(
	node *tree_sitter.Node,
	source []byte,
	stringValues map[string]string,
) (string, bool) {
	if value, ok := treeStringLiteral(node, source); ok {
		return value, true
	}

	if node == nil || node.Kind() != "identifier" {
		return "", false
	}

	name := strings.TrimSpace(node.Utf8Text(source))
	value, exists := stringValues[name]

	return value, exists
}

func resolveObjectStringProperties(
	node *tree_sitter.Node,
	source []byte,
) map[string]string {
	values := make(map[string]string)

	if node == nil || node.Kind() != "object" {
		return values
	}

	for index := uint(0); index < node.NamedChildCount(); index++ {
		pair := node.NamedChild(index)
		if pair == nil || pair.Kind() != "pair" {
			continue
		}

		keyNode := pair.ChildByFieldName("key")
		valueNode := pair.ChildByFieldName("value")

		if keyNode == nil || valueNode == nil {
			continue
		}

		value, ok := treeStringLiteral(valueNode, source)
		if !ok {
			continue
		}

		key := strings.TrimSpace(keyNode.Utf8Text(source))
		key = strings.Trim(key, `"'`)

		if key != "" {
			values[key] = value
		}
	}

	return values
}

func resolveLocalObjectNode(
	body *tree_sitter.Node,
	node *tree_sitter.Node,
	source []byte,
) *tree_sitter.Node {
	if node == nil {
		return nil
	}

	if node.Kind() == "object" {
		return node
	}

	if node.Kind() != "identifier" {
		return node
	}

	targetName := strings.TrimSpace(
		node.Utf8Text(source),
	)

	if targetName == "" {
		return node
	}

	var resolved *tree_sitter.Node

	walkTree(body, func(candidate *tree_sitter.Node) {
		if resolved != nil ||
			candidate.Kind() != "variable_declarator" {
			return
		}

		nameNode := candidate.ChildByFieldName("name")
		valueNode := candidate.ChildByFieldName("value")

		if nameNode == nil || valueNode == nil {
			return
		}

		if nameNode.Kind() != "identifier" ||
			valueNode.Kind() != "object" {
			return
		}

		name := strings.TrimSpace(
			nameNode.Utf8Text(source),
		)

		if name == targetName {
			resolved = valueNode
		}
	})

	if resolved != nil {
		return resolved
	}

	return node
}
