package jsintel

import (
	"fmt"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

func findNamedDataFlowFunctions(
	root *tree_sitter.Node,
	source []byte,
) map[string]dataFlowFunction {
	functions := make(map[string]dataFlowFunction)

	walkTree(root, func(node *tree_sitter.Node) {
		switch node.Kind() {
		case "function_declaration":
			nameNode := node.ChildByFieldName("name")
			parametersNode := node.ChildByFieldName("parameters")
			bodyNode := node.ChildByFieldName("body")

			if nameNode == nil ||
				parametersNode == nil ||
				bodyNode == nil {
				return
			}

			name := strings.TrimSpace(nameNode.Utf8Text(source))
			if name == "" {
				return
			}

			functions[name] = buildDataFlowFunction(
				parametersNode,
				bodyNode,
				source,
			)
		case "variable_declarator":
			nameNode := node.ChildByFieldName("name")
			valueNode := node.ChildByFieldName("value")

			if nameNode == nil || valueNode == nil {
				return
			}

			if nameNode.Kind() != "identifier" ||
				valueNode.Kind() != "arrow_function" {
				return
			}

			name := strings.TrimSpace(nameNode.Utf8Text(source))
			if name == "" {
				return
			}

			parametersNode := valueNode.ChildByFieldName("parameters")
			bodyNode := valueNode.ChildByFieldName("body")

			if parametersNode == nil || bodyNode == nil {
				return
			}

			functions[name] = buildDataFlowFunction(
				parametersNode,
				bodyNode,
				source,
			)
		}
	})

	return functions
}

func findFetchDataFlowParameters(
	body *tree_sitter.Node,
	source []byte,
	parameters []string,
) dataFlowFunction {
	parameterSet := make(map[string]bool)

	for _, parameter := range parameters {
		parameterSet[parameter] = true
	}

	result := dataFlowFunction{
		FetchMethods: make([]string, 0),
	}

	walkTree(body, func(node *tree_sitter.Node) {
		if node.Kind() != "call_expression" {
			return
		}

		function := node.ChildByFieldName("function")
		arguments := node.ChildByFieldName("arguments")

		if function == nil || arguments == nil {
			return
		}

		if !isFetchCall(function, source) {
			return
		}

		if arguments.NamedChildCount() >= 1 {
			urlNode := arguments.NamedChild(0)

			if urlNode != nil {
				switch urlNode.Kind() {
				case "identifier":
					name := strings.TrimSpace(
						urlNode.Utf8Text(source),
					)

					if parameterSet[name] {
						result.FetchURLParam = name
					}

				case "member_expression":
					object := urlNode.ChildByFieldName("object")
					property := urlNode.ChildByFieldName("property")

					if object != nil && property != nil {
						name := strings.TrimSpace(
							object.Utf8Text(source),
						)

						propertyName := strings.TrimSpace(
							property.Utf8Text(source),
						)

						if parameterSet[name] {
							result.FetchURLParam = name
							result.FetchURLProperty = propertyName
						}
					}

				case "new_expression":
					constructor :=
						urlNode.ChildByFieldName("constructor")

					requestArguments :=
						urlNode.ChildByFieldName("arguments")

					if constructor == nil ||
						requestArguments == nil {
						break
					}

					if strings.TrimSpace(
						constructor.Utf8Text(source),
					) != "Request" {
						break
					}

					if requestArguments.NamedChildCount() >= 1 {
						requestURL :=
							requestArguments.NamedChild(0)

						switch requestURL.Kind() {
						case "string":
							if resolved, ok :=
								treeStringLiteral(
									requestURL,
									source,
								); ok {
								result.FetchStaticPath = resolved
							}

						case "member_expression":
							object :=
								requestURL.ChildByFieldName(
									"object",
								)

							property :=
								requestURL.ChildByFieldName(
									"property",
								)

							if object == nil || property == nil {
								break
							}

							name := strings.TrimSpace(
								object.Utf8Text(source),
							)

							propertyName := strings.TrimSpace(
								property.Utf8Text(source),
							)

							if parameterSet[name] ||
								name == "this" {
								result.RequestURLParam = name
								result.RequestURLProperty =
									propertyName
							}
						}
					}

					if requestArguments.NamedChildCount() >= 2 {
						requestOptions :=
							requestArguments.NamedChild(1)

						requestOptions = resolveLocalObjectNode(
							body,
							requestOptions,
							source,
						)

						result.FetchMethods = append(
							result.FetchMethods,
							findStaticRequestMethods(
								requestOptions,
								source,
							)...,
						)

						findRequestMethodBinding(
							requestOptions,
							source,
							parameterSet,
							&result,
						)
					}
				}
			}
		}

		if arguments.NamedChildCount() < 2 {
			return
		}

		options := arguments.NamedChild(1)
		if options == nil || options.Kind() != "object" {
			return
		}

		findFetchMethodBinding(
			options,
			source,
			parameterSet,
			&result,
		)
	})

	return result
}

func findFetchMethodBinding(
	options *tree_sitter.Node,
	source []byte,
	parameterSet map[string]bool,
	result *dataFlowFunction,
) {
	for index := uint(0); index < options.NamedChildCount(); index++ {

		property := options.NamedChild(index)
		if property == nil {
			continue
		}

		switch property.Kind() {
		case "shorthand_property_identifier":
			name := strings.TrimSpace(
				property.Utf8Text(source),
			)

			if name == "method" && parameterSet[name] {
				result.FetchMethodParam = name
			}

		case "pair":
			key := property.ChildByFieldName("key")
			value := property.ChildByFieldName("value")

			if key == nil || value == nil {
				continue
			}

			keyName := strings.Trim(
				strings.TrimSpace(key.Utf8Text(source)),
				`"'`,
			)

			if keyName != "method" {
				continue
			}

			switch value.Kind() {
			case "identifier":
				name := strings.TrimSpace(
					value.Utf8Text(source),
				)

				if parameterSet[name] {
					result.FetchMethodParam = name
				}

			case "member_expression":
				object := value.ChildByFieldName("object")
				propertyNode :=
					value.ChildByFieldName("property")

				if object == nil || propertyNode == nil {
					continue
				}

				name := strings.TrimSpace(
					object.Utf8Text(source),
				)

				propertyName := strings.TrimSpace(
					propertyNode.Utf8Text(source),
				)

				if parameterSet[name] {
					result.FetchMethodParam = name
					result.FetchMethodProperty = propertyName
				}

			case "ternary_expression":
				addConditionalMethods(
					value,
					source,
					&result.FetchMethods,
				)
			}
		}
	}
}

func findRequestMethodBinding(
	options *tree_sitter.Node,
	source []byte,
	parameterSet map[string]bool,
	result *dataFlowFunction,
) {
	if options == nil || options.Kind() != "object" {
		return
	}

	for index := uint(0); index < options.NamedChildCount(); index++ {

		pair := options.NamedChild(index)
		if pair == nil || pair.Kind() != "pair" {
			continue
		}

		key := pair.ChildByFieldName("key")
		value := pair.ChildByFieldName("value")

		if key == nil || value == nil {
			continue
		}

		keyName := strings.Trim(
			strings.TrimSpace(key.Utf8Text(source)),
			`"'`,
		)

		if keyName != "method" {
			continue
		}

		switch value.Kind() {
		case "member_expression":
			object := value.ChildByFieldName("object")
			property := value.ChildByFieldName("property")

			if object == nil || property == nil {
				continue
			}

			name := strings.TrimSpace(
				object.Utf8Text(source),
			)

			propertyName := strings.TrimSpace(
				property.Utf8Text(source),
			)

			if parameterSet[name] || name == "this" {
				result.RequestMethodParam = name
				result.RequestMethodProperty = propertyName
			}

		case "ternary_expression":
			addConditionalMethods(
				value,
				source,
				&result.FetchMethods,
			)
		}
	}
}

func findStringVariables(
	root *tree_sitter.Node,
	source []byte,
) map[string]string {
	values := make(map[string]string)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "variable_declarator" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		valueNode := node.ChildByFieldName("value")

		if nameNode == nil || valueNode == nil {
			return
		}

		if nameNode.Kind() != "identifier" {
			return
		}

		value, ok := treeStringLiteral(valueNode, source)
		if !ok {
			return
		}

		name := strings.TrimSpace(nameNode.Utf8Text(source))
		if name != "" {
			values[name] = value
		}
	})

	return values
}

func findAxiosClientNames(
	root *tree_sitter.Node,
	source []byte,
) map[string]bool {
	clients := make(map[string]bool)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "variable_declarator" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		valueNode := node.ChildByFieldName("value")

		if nameNode == nil || valueNode == nil {
			return
		}

		if valueNode.Kind() != "call_expression" {
			return
		}

		function := valueNode.ChildByFieldName("function")
		if function == nil {
			return
		}

		callee := strings.ToLower(
			strings.TrimSpace(function.Utf8Text(source)),
		)

		if callee != "axios.create" {
			return
		}

		name := strings.TrimSpace(nameNode.Utf8Text(source))
		if name != "" {
			clients[name] = true
		}
	})

	return clients
}

func findHTTPCallScopes(source []byte) ([]javaScriptScope, error) {
	tree, err := parseJavaScriptTree(source)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		return nil, fmt.Errorf("tree-sitter returned nil root node")
	}
	axiosClients := findAxiosClientNames(root, source)
	scopes := make([]javaScriptScope, 0)
	seen := make(map[string]bool)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "call_expression" {
			return
		}

		if !isHTTPCallNode(node, source, axiosClients) {
			return
		}

		scope := nearestJavaScriptScope(node)
		if scope == nil {
			return
		}

		start := scope.StartByte()
		end := scope.EndByte()

		if start >= end || end > uint(len(source)) {
			return
		}

		key := fmt.Sprintf("%d:%d", start, end)
		if seen[key] {
			return
		}

		seen[key] = true

		scopes = append(scopes, javaScriptScope{
			Kind:   scope.Kind(),
			Start:  start,
			End:    end,
			Source: scope.Utf8Text(source),
		})
	})
	return scopes, nil
}

func findStaticRequestMethods(
	options *tree_sitter.Node,
	source []byte,
) []string {
	methods := make([]string, 0)

	if options == nil || options.Kind() != "object" {
		return methods
	}

	for index := uint(0); index < options.NamedChildCount(); index++ {

		pair := options.NamedChild(index)
		if pair == nil || pair.Kind() != "pair" {
			continue
		}

		key := pair.ChildByFieldName("key")
		value := pair.ChildByFieldName("value")

		if key == nil || value == nil {
			continue
		}

		keyName := strings.Trim(
			strings.TrimSpace(key.Utf8Text(source)),
			`"'`,
		)

		if keyName != "method" {
			continue
		}

		method, ok := treeStringLiteral(value, source)
		if !ok {
			continue
		}

		method = strings.ToUpper(method)

		if !containsString(methods, method) {
			methods = append(methods, method)
		}
	}

	return methods
}
