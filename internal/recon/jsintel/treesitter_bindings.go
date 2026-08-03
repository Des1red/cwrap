package jsintel

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

func findDataFlowBindings(
	root *tree_sitter.Node,
	source []byte,
	stringValues map[string]string,
) map[string]dataFlowBinding {
	bindings := make(map[string]dataFlowBinding)

	registerFunctionBindings(
		root,
		source,
		bindings,
	)

	classes := findDataFlowClasses(
		root,
		source,
	)

	registerInstanceBindings(
		root,
		source,
		stringValues,
		classes,
		bindings,
	)

	return bindings
}

func registerFunctionBindings(
	root *tree_sitter.Node,
	source []byte,
	bindings map[string]dataFlowBinding,
) {
	for name, target := range findNamedDataFlowFunctions(root, source) {

		bindings[name] = dataFlowBinding{
			Target: target,
			Values: newDataFlowCallValues(),
		}
	}
}

func findDataFlowClasses(
	root *tree_sitter.Node,
	source []byte,
) map[string]dataFlowClass {
	classes := make(map[string]dataFlowClass)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "class_declaration" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		bodyNode := node.ChildByFieldName("body")

		if nameNode == nil || bodyNode == nil {
			return
		}

		className := strings.TrimSpace(
			nameNode.Utf8Text(source),
		)

		if className == "" {
			return
		}

		class := dataFlowClass{
			FieldParameters: make(map[string]string),
			Methods:         make(map[string]dataFlowFunction),
			Mutators:        make(map[string]dataFlowMutator),
		}

		for index := uint(0); index < bodyNode.NamedChildCount(); index++ {

			methodNode := bodyNode.NamedChild(index)

			if methodNode == nil ||
				methodNode.Kind() != "method_definition" {
				continue
			}

			name := methodNode.ChildByFieldName("name")
			parameters :=
				methodNode.ChildByFieldName("parameters")
			body := methodNode.ChildByFieldName("body")

			if name == nil ||
				parameters == nil ||
				body == nil {
				continue
			}

			methodName := strings.TrimSpace(
				name.Utf8Text(source),
			)

			if methodName == "constructor" {
				class.ConstructorParameters =
					collectDataFlowParameters(
						parameters,
						source,
					)

				findConstructorBindings(
					body,
					source,
					class.ConstructorParameters,
					class.FieldParameters,
				)

				continue
			}

			registerDataFlowClassMethod(
				&class,
				methodName,
				parameters,
				body,
				source,
			)
		}

		if len(class.Methods) > 0 {
			classes[className] = class
		}
	})
	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "function_declaration" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		parametersNode := node.ChildByFieldName("parameters")
		bodyNode := node.ChildByFieldName("body")

		if nameNode == nil ||
			parametersNode == nil ||
			bodyNode == nil {
			return
		}

		className := strings.TrimSpace(
			nameNode.Utf8Text(source),
		)
		if className == "" {
			return
		}

		class, exists := classes[className]
		if !exists {
			class = dataFlowClass{
				FieldParameters: make(map[string]string),
				Methods:         make(map[string]dataFlowFunction),
				Mutators:        make(map[string]dataFlowMutator),
			}
		}

		constructorParameters := collectDataFlowParameters(
			parametersNode,
			source,
		)

		findConstructorBindings(
			bodyNode,
			source,
			constructorParameters,
			class.FieldParameters,
		)

		class.ConstructorParameters = constructorParameters
		classes[className] = class
	})
	prototypeAliases := make(map[string]string)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "assignment_expression" {
			return
		}

		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")
		if left != nil &&
			right != nil &&
			left.Kind() == "identifier" &&
			right.Kind() == "member_expression" {

			object := right.ChildByFieldName("object")
			property := right.ChildByFieldName("property")

			if object != nil &&
				property != nil &&
				strings.TrimSpace(
					property.Utf8Text(source),
				) == "prototype" {

				aliasName := strings.TrimSpace(
					left.Utf8Text(source),
				)

				className := strings.TrimSpace(
					object.Utf8Text(source),
				)

				prototypeAliases[aliasName] = className

				return
			}
		}
		if left == nil ||
			right == nil ||
			left.Kind() != "member_expression" ||
			right.Kind() != "function_expression" {
			return
		}

		methodNameNode := left.ChildByFieldName("property")
		methodObject := left.ChildByFieldName("object")

		if methodNameNode == nil || methodObject == nil {
			return
		}

		className := ""

		switch methodObject.Kind() {
		case "member_expression":
			classNode :=
				methodObject.ChildByFieldName("object")

			prototypeProperty :=
				methodObject.ChildByFieldName("property")

			if classNode == nil || prototypeProperty == nil {
				return
			}

			if strings.TrimSpace(
				prototypeProperty.Utf8Text(source),
			) != "prototype" {
				return
			}

			className = strings.TrimSpace(
				classNode.Utf8Text(source),
			)

		case "identifier":
			aliasName := strings.TrimSpace(
				methodObject.Utf8Text(source),
			)

			className = prototypeAliases[aliasName]

		default:
			return
		}

		if className == "" {
			return
		}

		methodName := strings.TrimSpace(
			methodNameNode.Utf8Text(source),
		)

		class, exists := classes[className]
		if !exists || methodName == "" {
			return
		}

		parametersNode :=
			right.ChildByFieldName("parameters")
		bodyNode := right.ChildByFieldName("body")

		if parametersNode == nil || bodyNode == nil {
			return
		}

		registerDataFlowClassMethod(
			&class,
			methodName,
			parametersNode,
			bodyNode,
			source,
		)

		classes[className] = class
	})

	return classes
}

func findConstructorBindings(
	body *tree_sitter.Node,
	source []byte,
	parameters []string,
	fields map[string]string,
) {
	parameterSet := make(map[string]bool)

	for _, parameter := range parameters {
		parameterSet[parameter] = true
	}

	walkTree(body, func(node *tree_sitter.Node) {
		if node.Kind() != "assignment_expression" {
			return
		}

		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")

		if left == nil ||
			right == nil ||
			left.Kind() != "member_expression" ||
			right.Kind() != "identifier" {
			return
		}

		object := left.ChildByFieldName("object")
		property := left.ChildByFieldName("property")

		if object == nil || property == nil {
			return
		}

		if strings.TrimSpace(
			object.Utf8Text(source),
		) != "this" {
			return
		}

		parameter := strings.TrimSpace(
			right.Utf8Text(source),
		)

		if !parameterSet[parameter] {
			return
		}

		field := strings.TrimSpace(
			property.Utf8Text(source),
		)

		if field != "" {
			fields[field] = parameter
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
	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "variable_declarator" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		valueNode := node.ChildByFieldName("value")

		if nameNode == nil ||
			valueNode == nil ||
			nameNode.Kind() != "identifier" ||
			valueNode.Kind() != "new_expression" {
			return
		}

		constructor :=
			valueNode.ChildByFieldName("constructor")

		arguments :=
			valueNode.ChildByFieldName("arguments")

		if constructor == nil || arguments == nil {
			return
		}

		className := strings.TrimSpace(
			constructor.Utf8Text(source),
		)

		class, exists := classes[className]
		if !exists {
			return
		}

		constructorTarget := dataFlowFunction{
			Parameters: class.ConstructorParameters,
		}

		constructorValues := resolveDataFlowCallValues(
			constructorTarget,
			arguments,
			source,
			stringValues,
		)

		fields := make(map[string]string)

		for field, parameter := range class.FieldParameters {
			if value, exists :=
				constructorValues.Scalars[parameter]; exists {

				fields[field] = value
			}
		}

		instanceName := strings.TrimSpace(
			nameNode.Utf8Text(source),
		)

		if instanceName == "" {
			return
		}

		instances[instanceName] = dataFlowInstance{
			ClassName: className,
			Fields:    fields,
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

		instanceName := strings.TrimSpace(
			object.Utf8Text(source),
		)

		methodName := strings.TrimSpace(
			property.Utf8Text(source),
		)

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
