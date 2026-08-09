package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

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

	walkAssignmentExpressions(body, func(left, right *tree_sitter.Node) {
		if left.Kind() != "member_expression" ||
			right.Kind() != "identifier" {
			return
		}

		object := left.ChildByFieldName("object")
		property := left.ChildByFieldName("property")

		if object == nil || property == nil {
			return
		}

		if nodeText(object, source) != "this" {
			return
		}

		parameter := nodeText(right, source)

		if !parameterSet[parameter] {
			return
		}

		field := nodeText(property, source)

		if field != "" {
			fields[field] = parameter
		}
	})
}

func findDataFlowBindings(
	root *tree_sitter.Node,
	source []byte,
	stringValues map[string]string,
) map[string]dataFlowBinding {
	bindings := make(map[string]dataFlowBinding)

	classes := findDataFlowClasses(
		root,
		source,
	)

	registerFunctionBindings(
		root,
		source,
		classes,
		bindings,
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
