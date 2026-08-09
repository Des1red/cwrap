package treesitter

import tree_sitter "github.com/tree-sitter/go-tree-sitter"

// walkVariableDeclarators walks variable_declarator nodes, calling
// visit with the name and value child nodes. Skips declarators
// missing either side. Callers are responsible for checking
// nameNode.Kind() if they require a plain identifier binding.
func walkVariableDeclarators(
	root *tree_sitter.Node,
	visit func(nameNode, valueNode *tree_sitter.Node),
) {
	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "variable_declarator" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		valueNode := node.ChildByFieldName("value")

		if nameNode == nil || valueNode == nil {
			return
		}

		visit(nameNode, valueNode)
	})
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

// walkNamedFunctionLikeNodes walks named function declarations and
// identifier-bound arrow function variable declarators (e.g.
// `function foo() {}` or `const foo = () => {}`), calling visit with
// the resolved name, parameters node, and body node. Skips anything
// missing a name, parameters, or body, and skips arrow functions bound
// to a destructuring pattern rather than a plain identifier.
func walkNamedFunctionLikeNodes(
	root *tree_sitter.Node,
	source []byte,
	visit func(name string, parametersNode, bodyNode *tree_sitter.Node),
) {
	walkTree(root, func(node *tree_sitter.Node) {
		var nameNode *tree_sitter.Node
		var parametersNode *tree_sitter.Node
		var bodyNode *tree_sitter.Node

		switch node.Kind() {
		case "function_declaration":
			nameNode = node.ChildByFieldName("name")
			parametersNode = node.ChildByFieldName("parameters")
			bodyNode = node.ChildByFieldName("body")

		case "variable_declarator":
			valueNode := node.ChildByFieldName("value")
			if valueNode == nil ||
				valueNode.Kind() != "arrow_function" {
				return
			}

			nameNode = node.ChildByFieldName("name")
			if nameNode == nil || nameNode.Kind() != "identifier" {
				return
			}

			parametersNode = valueNode.ChildByFieldName("parameters")
			bodyNode = valueNode.ChildByFieldName("body")

		default:
			return
		}

		if nameNode == nil ||
			parametersNode == nil ||
			bodyNode == nil {
			return
		}

		name := nodeText(nameNode, source)
		if name == "" {
			return
		}

		visit(name, parametersNode, bodyNode)
	})
}

// walkAssignmentExpressions walks assignment_expression nodes, calling
// visit with the left and right child nodes. Skips assignments missing
// either side. Callers are responsible for checking left.Kind() and
// right.Kind() for the shapes they require.
func walkAssignmentExpressions(
	root *tree_sitter.Node,
	visit func(left, right *tree_sitter.Node),
) {
	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "assignment_expression" {
			return
		}

		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")

		if left == nil || right == nil {
			return
		}

		visit(left, right)
	})
}

// iterateObjectProperties calls visit for each non-nil named child of
// an object literal node, regardless of property kind (pair,
// shorthand_property_identifier, spread_element, etc). No-op if
// options is nil or not an object.
func iterateObjectProperties(
	options *tree_sitter.Node,
	visit func(property *tree_sitter.Node),
) {
	if options == nil || options.Kind() != "object" {
		return
	}

	for index := uint(0); index < options.NamedChildCount(); index++ {
		property := options.NamedChild(index)
		if property == nil {
			continue
		}

		visit(property)
	}
}
