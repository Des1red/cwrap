package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// lookupObjectValue reads a resolved property off a call argument that
// was captured as an object literal, e.g. options.method. Returns
// false if the parameter was never captured or didn't have that
// property — same as the two-step map lookup it replaces.
func lookupObjectValue(
	values dataFlowCallValues,
	param, property string,
) (string, bool) {
	properties := values.Objects[param]
	value, exists := properties[property]
	return value, exists
}

func resolveDataFlowMethods(
	target dataFlowFunction,
	values dataFlowCallValues,
) []string {
	if len(target.FetchMethods) > 0 {
		return target.FetchMethods
	}

	if target.RequestMethodProperty != "" {
		if resolved, exists := lookupObjectValue(
			values,
			target.RequestMethodParam,
			target.RequestMethodProperty,
		); exists {
			return []string{strings.ToUpper(resolved)}
		}
	}

	if target.FetchMethodProperty != "" {
		if resolved, exists := lookupObjectValue(
			values,
			target.FetchMethodParam,
			target.FetchMethodProperty,
		); exists {
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

	className := nodeText(constructor, source)

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
		path, exists := lookupObjectValue(
			values,
			target.RequestURLParam,
			target.RequestURLProperty,
		)

		return path,
			"fetch-request-object-dataflow-ast",
			exists
	}

	if target.FetchURLProperty != "" {
		path, exists := lookupObjectValue(
			values,
			target.FetchURLParam,
			target.FetchURLProperty,
		)
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

	name := nodeText(node, source)
	value, exists := stringValues[name]

	return value, exists
}

func resolveObjectStringProperties(
	node *tree_sitter.Node,
	source []byte,
) map[string]string {
	values := make(map[string]string)

	forEachObjectPair(node, source, func(
		keyName string,
		keyNode, valueNode *tree_sitter.Node,
	) {
		value, ok := treeStringLiteral(valueNode, source)
		if !ok {
			return
		}

		if keyName != "" {
			values[keyName] = value
		}
	})

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

	targetName := nodeText(node, source)

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

		name := nodeText(nameNode, source)

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
		name := nodeText(node, source)

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

		functionName := nodeText(function, source)

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
		name := nodeText(node, source)

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

	objectName := nodeText(object, source)

	propertyName := nodeText(propertyNode, source)

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
		_, exists := lookupObjectValue(
			values,
			target.RequestMethodParam,
			target.RequestMethodProperty,
		)

		return exists
	}

	if target.FetchMethodProperty != "" {
		_, exists := lookupObjectValue(
			values,
			target.FetchMethodParam,
			target.FetchMethodProperty,
		)

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
