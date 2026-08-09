package treesitter

import tree_sitter "github.com/tree-sitter/go-tree-sitter"

func registerFunctionBindings(
	root *tree_sitter.Node,
	source []byte,
	classes map[string]dataFlowClass,
	bindings map[string]dataFlowBinding,
) {
	functions := findNamedDataFlowFunctions(
		root,
		source,
	)

	for name, target := range functions {
		bindings[name] = dataFlowBinding{
			Target: target,
			Values: newDataFlowCallValues(),
		}
	}

	walkNamedFunctionLikeNodes(root, source, func(
		name string,
		parametersNode, bodyNode *tree_sitter.Node,
	) {
		parameters := collectDataFlowParameters(
			parametersNode,
			source,
		)

		delegated, ok := findDelegatedDataFlowFunction(
			bodyNode,
			source,
			parameters,
			classes,
		)
		if !ok {
			return
		}

		bindings[name] = dataFlowBinding{
			Target: delegated,
			Values: newDataFlowCallValues(),
		}
	})
}

func registerInstanceBindings(
	root *tree_sitter.Node,
	source []byte,
	stringValues map[string]string,
	classes map[string]dataFlowClass,
	bindings map[string]dataFlowBinding,
) {
	instances := make(map[string]dataFlowInstance)

	// First pass: create instances and bind constructor fields.
	registerInstance := func(
		nameNode *tree_sitter.Node,
		valueNode *tree_sitter.Node,
	) {
		if nameNode == nil ||
			valueNode == nil ||
			nameNode.Kind() != "identifier" {
			return
		}

		instance, ok := resolveNewDataFlowInstance(
			valueNode,
			source,
			stringValues,
			classes,
		)
		if !ok {
			return
		}

		instanceName := nodeText(nameNode, source)

		if instanceName == "" {
			return
		}

		instances[instanceName] = instance
	}

	walkTree(root, func(node *tree_sitter.Node) {
		switch node.Kind() {
		case "variable_declarator":
			registerInstance(
				node.ChildByFieldName("name"),
				node.ChildByFieldName("value"),
			)

		case "assignment_expression":
			registerInstance(
				node.ChildByFieldName("left"),
				node.ChildByFieldName("right"),
			)
		}
	})

	// Second pass: apply mutator calls such as client.open(...).
	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "call_expression" {
			return
		}

		function := node.ChildByFieldName("function")
		arguments := node.ChildByFieldName("arguments")

		if function == nil ||
			arguments == nil ||
			function.Kind() != "member_expression" {
			return
		}

		object := function.ChildByFieldName("object")
		property := function.ChildByFieldName("property")

		if object == nil || property == nil {
			return
		}

		instanceName := nodeText(object, source)

		methodName := nodeText(property, source)

		instance, exists := instances[instanceName]
		if !exists {
			return
		}

		class, exists := classes[instance.ClassName]
		if !exists {
			return
		}

		mutator, exists := class.Mutators[methodName]
		if !exists {
			return
		}

		mutatorTarget := dataFlowFunction{
			Parameters: mutator.Parameters,
		}

		callValues := resolveDataFlowCallValues(
			mutatorTarget,
			arguments,
			source,
			stringValues,
		)

		for field, parameter := range mutator.FieldParameters {

			if value, exists :=
				callValues.Scalars[parameter]; exists {

				instance.Fields[field] = value
			}
		}

		instances[instanceName] = instance
	})

	// Third pass: expose each request method as a normal callable binding.
	for instanceName, instance := range instances {
		class, exists := classes[instance.ClassName]
		if !exists {
			continue
		}

		for methodName, target := range class.Methods {
			values := newDataFlowCallValues()

			values.Objects["this"] = instance.Fields

			bindings[instanceName+"."+methodName] =
				dataFlowBinding{
					Target: target,
					Values: values,
				}
		}
	}
}

func registerDataFlowClassMethod(
	class *dataFlowClass,
	methodName string,
	parametersNode *tree_sitter.Node,
	bodyNode *tree_sitter.Node,
	source []byte,
	classes map[string]dataFlowClass,
) {
	target := buildDataFlowFunction(
		parametersNode,
		bodyNode,
		source,
	)

	hasEndpoint := target.FetchStaticPath != "" ||
		target.FetchURLParam != "" ||
		target.FetchURLProperty != "" ||
		target.RequestURLParam != "" ||
		target.RequestURLProperty != ""

	if hasEndpoint {
		class.Methods[methodName] = target
		return
	}

	parameters := collectDataFlowParameters(
		parametersNode,
		source,
	)

	if delegated, ok := findDelegatedDataFlowFunction(
		bodyNode,
		source,
		parameters,
		classes,
	); ok {
		class.Methods[methodName] = delegated
		delete(class.Mutators, methodName)
		return
	}

	fieldParameters := make(map[string]string)

	findConstructorBindings(
		bodyNode,
		source,
		parameters,
		fieldParameters,
	)

	if len(fieldParameters) == 0 {
		return
	}

	class.Mutators[methodName] = dataFlowMutator{
		Parameters:      parameters,
		FieldParameters: fieldParameters,
	}
}
