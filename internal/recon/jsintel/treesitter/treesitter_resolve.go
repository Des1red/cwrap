package treesitter

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

func resolveNewDataFlowInstance(
	node *tree_sitter.Node,
	source []byte,
	stringValues map[string]string,
	classes map[string]dataFlowClass,
) (dataFlowInstance, bool) {
	if node == nil {
		return dataFlowInstance{}, false
	}

	if node.Kind() == "ternary_expression" {
		for _, field := range []string{
			"consequence",
			"alternative",
		} {
			branch := node.ChildByFieldName(field)

			instance, ok := resolveNewDataFlowInstance(
				branch,
				source,
				stringValues,
				classes,
			)
			if ok {
				return instance, true
			}
		}

		return dataFlowInstance{}, false
	}

	if node.Kind() != "new_expression" {
		return dataFlowInstance{}, false
	}

	constructor := node.ChildByFieldName("constructor")
	arguments := node.ChildByFieldName("arguments")

	if constructor == nil || arguments == nil {
		return dataFlowInstance{}, false
	}

	className := strings.TrimSpace(
		constructor.Utf8Text(source),
	)

	class, exists := classes[className]
	if !exists {
		return dataFlowInstance{}, false
	}

	instance := dataFlowInstance{
		ClassName:    className,
		Fields:       make(map[string]string),
		ObjectFields: make(map[string]dataFlowInstance),
	}

	constructorTarget := dataFlowFunction{
		Parameters: class.ConstructorParameters,
	}

	values := resolveDataFlowCallValues(
		constructorTarget,
		arguments,
		source,
		stringValues,
	)

	for field, parameter := range class.FieldParameters {
		if value, exists := values.Scalars[parameter]; exists {
			instance.Fields[field] = value
		}
	}

	argumentIndex := 0

	for index := uint(0); index < arguments.NamedChildCount(); index++ {
		argument := arguments.NamedChild(index)
		if argument == nil {
			continue
		}

		if argumentIndex >= len(class.ConstructorParameters) {
			break
		}

		parameter := class.ConstructorParameters[argumentIndex]
		argumentIndex++

		childInstance, ok := resolveNewDataFlowInstance(
			argument,
			source,
			stringValues,
			classes,
		)
		if !ok {
			continue
		}

		for field, fieldParameter := range class.FieldParameters {
			if fieldParameter == parameter {
				instance.ObjectFields[field] = childInstance
			}
		}
	}

	return instance, true
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

func resolveDataFlowParameterReference(
	node *tree_sitter.Node,
	source []byte,
	parameterSet map[string]bool,
) (string, bool) {
	if node == nil {
		return "", false
	}

	if node.Kind() == "identifier" {
		name := strings.TrimSpace(
			node.Utf8Text(source),
		)

		return name, parameterSet[name]
	}

	// Handles wrappers such as String(url).
	if node.Kind() == "call_expression" {
		function := node.ChildByFieldName("function")
		arguments := node.ChildByFieldName("arguments")

		if function == nil ||
			arguments == nil ||
			arguments.NamedChildCount() != 1 {
			return "", false
		}

		functionName := strings.TrimSpace(
			function.Utf8Text(source),
		)

		switch functionName {
		case "String":
			return resolveDataFlowParameterReference(
				arguments.NamedChild(0),
				source,
				parameterSet,
			)
		}
	}

	return "", false
}

func resolveDelegatedDataFlowReference(
	node *tree_sitter.Node,
	source []byte,
	parameterSet map[string]bool,
	fieldParameters map[string]string,
) (
	parameter string,
	property string,
	ok bool,
) {
	if node == nil {
		return "", "", false
	}

	if node.Kind() == "identifier" {
		name := strings.TrimSpace(
			node.Utf8Text(source),
		)

		if parameterSet[name] {
			return name, "", true
		}

		return "", "", false
	}

	if node.Kind() != "member_expression" {
		return "", "", false
	}

	object := node.ChildByFieldName("object")
	propertyNode := node.ChildByFieldName("property")

	if object == nil || propertyNode == nil {
		return "", "", false
	}

	objectName := strings.TrimSpace(
		object.Utf8Text(source),
	)

	propertyName := strings.TrimSpace(
		propertyNode.Utf8Text(source),
	)

	if objectName == "this" {
		if parameter, exists :=
			fieldParameters[propertyName]; exists {

			return parameter, "", true
		}

		return "this", propertyName, true
	}

	if parameterSet[objectName] {
		return objectName, propertyName, true
	}

	return "", "", false
}

func isDataFlowMethodResolved(
	target dataFlowFunction,
	values dataFlowCallValues,
) bool {
	if len(target.FetchMethods) > 0 {
		return len(
			validHTTPMethods(target.FetchMethods),
		) > 0
	}

	if target.RequestMethodProperty != "" {
		properties := values.Objects[target.RequestMethodParam]

		_, exists :=
			properties[target.RequestMethodProperty]

		return exists
	}

	if target.FetchMethodProperty != "" {
		properties := values.Objects[target.FetchMethodParam]

		_, exists :=
			properties[target.FetchMethodProperty]

		return exists
	}

	if target.FetchMethodParam != "" {
		_, exists :=
			values.Scalars[target.FetchMethodParam]

		return exists
	}

	// No method binding means the normal fetch default is GET.
	return true
}
