package astp

import "github.com/dop251/goja/ast"

func (e *endpointASTExtractor) collectStatementConstants(
	statement ast.Statement,
) {
	switch node := statement.(type) {
	case *ast.ExpressionStatement:
		e.collectExpressionConstants(node.Expression)
	case *ast.VariableStatement:
		e.collectBindings(node.List)

		for _, binding := range node.List {
			if binding != nil {
				e.collectExpressionConstants(binding.Initializer)
			}
		}

	case *ast.LexicalDeclaration:
		e.collectBindings(node.List)

		for _, binding := range node.List {
			if binding != nil {
				e.collectExpressionConstants(binding.Initializer)
			}
		}

	case *ast.BlockStatement:
		for _, child := range node.List {
			e.collectStatementConstants(child)
		}

	case *ast.IfStatement:
		e.collectStatementConstants(node.Consequent)

		if node.Alternate != nil {
			e.collectStatementConstants(node.Alternate)
		}

	case *ast.WhileStatement:
		e.collectStatementConstants(node.Body)

	case *ast.DoWhileStatement:
		e.collectStatementConstants(node.Body)

	case *ast.ForStatement:
		e.collectStatementConstants(node.Body)

	case *ast.ForInStatement:
		e.collectStatementConstants(node.Body)

	case *ast.ForOfStatement:
		e.collectStatementConstants(node.Body)

	case *ast.TryStatement:
		if node.Body != nil {
			e.collectStatementConstants(node.Body)
		}

		if node.Catch != nil && node.Catch.Body != nil {
			e.collectStatementConstants(node.Catch.Body)
		}

		if node.Finally != nil {
			e.collectStatementConstants(node.Finally)
		}

	case *ast.FunctionDeclaration:
		if node.Function != nil && node.Function.Body != nil {
			e.collectStatementConstants(node.Function.Body)
		}
	}
}

func (e *endpointASTExtractor) collectExpressionConstants(
	expression ast.Expression,
) {
	if expression == nil {
		return
	}

	switch node := expression.(type) {
	case *ast.FunctionLiteral:
		if node.Body != nil {
			e.collectStatementConstants(node.Body)
		}

	case *ast.ArrowFunctionLiteral:
		switch body := node.Body.(type) {
		case *ast.BlockStatement:
			e.collectStatementConstants(body)

		case *ast.ExpressionBody:
			e.collectExpressionConstants(body.Expression)
		}

	case *ast.CallExpression:
		e.collectExpressionConstants(node.Callee)

		for _, argument := range node.ArgumentList {
			e.collectExpressionConstants(argument)
		}

	case *ast.AssignExpression:
		e.collectExpressionConstants(node.Left)
		e.collectExpressionConstants(node.Right)

	case *ast.ConditionalExpression:
		e.collectExpressionConstants(node.Consequent)
		e.collectExpressionConstants(node.Alternate)

	case *ast.ObjectLiteral:
		for _, property := range node.Value {
			keyed, ok := property.(*ast.PropertyKeyed)
			if !ok {
				continue
			}

			e.collectExpressionConstants(keyed.Value)
		}

	case *ast.ArrayLiteral:
		for _, item := range node.Value {
			e.collectExpressionConstants(item)
		}
	}
}
func (e *endpointASTExtractor) collectBindings(
	bindings []*ast.Binding,
) {
	/*
		Repeat until no additional constants can be resolved.

		This allows:

			const base = "/api";
			const endpoint = base + "/users";
	*/
	for {
		changed := false

		for _, binding := range bindings {
			if binding == nil || binding.Initializer == nil {
				continue
			}

			identifier, ok := binding.Target.(*ast.Identifier)
			if !ok {
				continue
			}

			name := identifier.Name.String()
			if name == "" {
				continue
			}

			if values, ok := e.resolveStringObject(binding.Initializer); ok {
				e.objectValues[name] = values
				continue
			}

			if baseURL, ok := e.resolveAxiosClient(binding.Initializer); ok {
				e.axiosClients[name] = baseURL
				continue
			}

			value, ok := e.resolveString(binding.Initializer)
			if !ok {
				continue
			}

			if existing, exists := e.constants[name]; exists &&
				existing == value {
				continue
			}

			e.constants[name] = value
			changed = true
		}

		if !changed {
			return
		}
	}
}
