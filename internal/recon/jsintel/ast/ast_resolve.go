package astp

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

func (e *endpointASTExtractor) walkStatement(
	statement ast.Statement,
) {
	switch node := statement.(type) {
	case *ast.ExpressionStatement:
		e.walkExpression(node.Expression)

	case *ast.VariableStatement:
		for _, binding := range node.List {
			if binding != nil {
				e.walkExpression(binding.Initializer)
			}
		}

	case *ast.LexicalDeclaration:
		for _, binding := range node.List {
			if binding != nil {
				e.walkExpression(binding.Initializer)
			}
		}

	case *ast.BlockStatement:
		for _, child := range node.List {
			e.walkStatement(child)
		}

	case *ast.IfStatement:
		e.walkExpression(node.Test)
		e.walkStatement(node.Consequent)

		if node.Alternate != nil {
			e.walkStatement(node.Alternate)
		}

	case *ast.WhileStatement:
		e.walkExpression(node.Test)
		e.walkStatement(node.Body)

	case *ast.DoWhileStatement:
		e.walkStatement(node.Body)
		e.walkExpression(node.Test)

	case *ast.ForStatement:
		e.walkExpression(node.Test)
		e.walkExpression(node.Update)
		e.walkStatement(node.Body)

	case *ast.ForInStatement:
		e.walkExpression(node.Source)
		e.walkStatement(node.Body)

	case *ast.ForOfStatement:
		e.walkExpression(node.Source)
		e.walkStatement(node.Body)

	case *ast.ReturnStatement:
		e.walkExpression(node.Argument)

	case *ast.ThrowStatement:
		e.walkExpression(node.Argument)

	case *ast.TryStatement:
		if node.Body != nil {
			e.walkStatement(node.Body)
		}

		if node.Catch != nil && node.Catch.Body != nil {
			e.walkStatement(node.Catch.Body)
		}

		if node.Finally != nil {
			e.walkStatement(node.Finally)
		}

	case *ast.FunctionDeclaration:
		if node.Function != nil && node.Function.Body != nil {
			e.walkStatement(node.Function.Body)
		}
	}
}

func (e *endpointASTExtractor) walkExpression(
	expression ast.Expression,
) {
	if expression == nil {
		return
	}

	switch node := expression.(type) {
	case *ast.CallExpression:
		e.handleCall(node)
		e.walkExpression(node.Callee)

		for _, argument := range node.ArgumentList {
			e.walkExpression(argument)
		}

	case *ast.AssignExpression:
		e.walkExpression(node.Left)
		e.walkExpression(node.Right)

	case *ast.BinaryExpression:
		e.walkExpression(node.Left)
		e.walkExpression(node.Right)

	case *ast.ConditionalExpression:
		e.walkExpression(node.Test)
		e.walkExpression(node.Consequent)
		e.walkExpression(node.Alternate)

	case *ast.DotExpression:
		e.walkExpression(node.Left)

	case *ast.BracketExpression:
		e.walkExpression(node.Left)
		e.walkExpression(node.Member)

	case *ast.ObjectLiteral:
		for _, property := range node.Value {
			switch property := property.(type) {
			case *ast.PropertyKeyed:
				e.walkExpression(property.Key)
				e.walkExpression(property.Value)

			case *ast.PropertyShort:
				e.walkExpression(property.Initializer)
			}
		}

	case *ast.ArrayLiteral:
		for _, item := range node.Value {
			e.walkExpression(item)
		}

	case *ast.TemplateLiteral:
		for _, embedded := range node.Expressions {
			e.walkExpression(embedded)
		}

	case *ast.SequenceExpression:
		for _, item := range node.Sequence {
			e.walkExpression(item)
		}

	case *ast.FunctionLiteral:
		if node.Body != nil {
			e.walkStatement(node.Body)
		}

	case *ast.ArrowFunctionLiteral:
		switch body := node.Body.(type) {
		case *ast.ExpressionBody:
			e.walkExpression(body.Expression)

		case *ast.BlockStatement:
			e.walkStatement(body)
		}
	}
}

func (e *endpointASTExtractor) resolveStringObject(
	expression ast.Expression,
) (map[string]string, bool) {
	object, ok := expression.(*ast.ObjectLiteral)
	if !ok {
		return nil, false
	}

	values := make(map[string]string)

	for _, property := range object.Value {
		keyed, ok := property.(*ast.PropertyKeyed)
		if !ok {
			continue
		}

		name, ok := propertyName(keyed.Key)
		if !ok || name == "" {
			continue
		}

		value, ok := e.resolveString(keyed.Value)
		if !ok {
			continue
		}

		values[name] = value
	}

	if len(values) == 0 {
		return nil, false
	}

	return values, true
}

func (e *endpointASTExtractor) resolveAxiosClient(
	expression ast.Expression,
) (string, bool) {
	call, ok := expression.(*ast.CallExpression)
	if !ok || len(call.ArgumentList) == 0 {
		return "", false
	}

	callee, ok := call.Callee.(*ast.DotExpression)
	if !ok {
		return "", false
	}

	left, ok := callee.Left.(*ast.Identifier)
	if !ok || left.Name.String() != "axios" {
		return "", false
	}

	if callee.Identifier.Name.String() != "create" {
		return "", false
	}

	config, ok := call.ArgumentList[0].(*ast.ObjectLiteral)
	if !ok {
		return "", false
	}

	for _, property := range config.Value {
		keyed, ok := property.(*ast.PropertyKeyed)
		if !ok {
			continue
		}

		name, ok := propertyName(keyed.Key)
		if !ok || name != "baseURL" {
			continue
		}

		return e.resolveString(keyed.Value)
	}

	return "", false
}

func (e *endpointASTExtractor) resolveString(
	expression ast.Expression,
) (string, bool) {
	if expression == nil {
		return "", false
	}

	switch node := expression.(type) {
	case *ast.StringLiteral:
		return node.Value.String(), true

	case *ast.Identifier:
		value, ok := e.constants[node.Name.String()]
		return value, ok

	case *ast.BinaryExpression:
		if node.Operator != token.PLUS {
			return "", false
		}

		left, ok := e.resolveString(node.Left)
		if !ok {
			return "", false
		}

		right, ok := e.resolveString(node.Right)
		if !ok {
			return "", false
		}

		return left + right, true

	case *ast.TemplateLiteral:
		return e.resolveTemplate(node)

	case *ast.DotExpression:
		identifier, ok := node.Left.(*ast.Identifier)
		if !ok {
			return "", false
		}

		object, exists := e.objectValues[identifier.Name.String()]
		if !exists {
			return "", false
		}

		value, exists := object[node.Identifier.Name.String()]
		return value, exists

	case *ast.BracketExpression:
		identifier, ok := node.Left.(*ast.Identifier)
		if !ok {
			return "", false
		}

		property, ok := e.resolveString(node.Member)
		if !ok {
			return "", false
		}

		object, exists := e.objectValues[identifier.Name.String()]
		if !exists {
			return "", false
		}

		value, exists := object[property]
		return value, exists
	default:
		return "", false
	}
}

func (e *endpointASTExtractor) resolveTemplate(
	template *ast.TemplateLiteral,
) (string, bool) {
	if template == nil || template.Tag != nil {
		return "", false
	}

	if len(template.Elements) != len(template.Expressions)+1 {
		return "", false
	}

	var result strings.Builder

	for index, element := range template.Elements {
		if element == nil || !element.Valid {
			return "", false
		}

		result.WriteString(element.Parsed.String())

		if index >= len(template.Expressions) {
			continue
		}

		value, ok := e.resolveString(template.Expressions[index])
		if !ok {
			return "", false
		}

		result.WriteString(value)
	}

	return result.String(), true
}
