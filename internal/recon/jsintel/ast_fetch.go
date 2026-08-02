package jsintel

import (
	"fmt"

	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

type endpointASTExtractor struct {
	constants    map[string]string
	objectValues map[string]map[string]string
	axiosClients map[string]string

	endpoints []JSEndpoint
	seen      map[string]bool
}

func extractEndpointsAST(source string) ([]JSEndpoint, error) {
	return parseEndpointProgram(source)
}

func parseEndpointProgram(source string) ([]JSEndpoint, error) {
	program, err := parser.ParseFile(nil, "", source, 0)
	if err != nil {
		return nil, err
	}

	if program == nil {
		return nil, fmt.Errorf("parser returned nil program")
	}

	extractor := &endpointASTExtractor{
		constants:    make(map[string]string),
		objectValues: make(map[string]map[string]string),
		axiosClients: make(map[string]string),
		seen:         make(map[string]bool),
	}

	for _, statement := range program.Body {
		extractor.collectStatementConstants(statement)
	}

	for _, statement := range program.Body {
		extractor.walkStatement(statement)
	}

	return extractor.endpoints, nil
}
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

func (e *endpointASTExtractor) handleCall(
	call *ast.CallExpression,

) {
	if call == nil || len(call.ArgumentList) == 0 {
		return
	}

	if e.handleFetchCall(call) {
		return
	}

	e.handleAxiosCall(call)

	e.handleXHRCall(call)

}

func (e *endpointASTExtractor) handleFetchCall(
	call *ast.CallExpression,

) bool {
	callee, ok := call.Callee.(*ast.Identifier)
	if !ok || callee.Name.String() != "fetch" {
		return false
	}

	path, ok := e.resolveString(call.ArgumentList[0])
	if !ok {
		return true
	}

	method := "GET"

	if len(call.ArgumentList) > 1 {
		if parsedMethod, ok := e.fetchMethod(call.ArgumentList[1]); ok {
			method = parsedMethod
		}
	}

	appendJSEndpoint(
		&e.endpoints,
		e.seen,
		method,
		path,
		"fetch-ast",
	)

	return true
}

func (e *endpointASTExtractor) handleAxiosCall(
	call *ast.CallExpression,

) bool {
	if call == nil || len(call.ArgumentList) == 0 {
		return false
	}

	if callee, ok := call.Callee.(*ast.Identifier); ok &&
		callee.Name.String() == "axios" {
		return e.handleAxiosConfigCall(call)
	}

	callee, ok := call.Callee.(*ast.DotExpression)
	if !ok {
		return false
	}

	left, ok := callee.Left.(*ast.Identifier)
	if !ok {
		return false
	}

	method := strings.ToUpper(callee.Identifier.Name.String())

	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
	default:
		return false
	}

	path, ok := e.resolveString(call.ArgumentList[0])
	if !ok {
		return true
	}

	clientName := left.Name.String()
	kind := "axios-ast"

	if clientName != "axios" {
		baseURL, exists := e.axiosClients[clientName]
		if !exists {
			return false
		}

		path = joinJSURL(baseURL, path)
		kind = "axios-instance-ast"
	}

	appendJSEndpoint(
		&e.endpoints,
		e.seen,
		method,
		path,
		kind,
	)

	return true
}

func (e *endpointASTExtractor) handleAxiosConfigCall(
	call *ast.CallExpression,

) bool {
	config, ok := call.ArgumentList[0].(*ast.ObjectLiteral)
	if !ok {
		return true
	}

	method := "GET"
	path := ""

	for _, property := range config.Value {
		keyed, ok := property.(*ast.PropertyKeyed)
		if !ok {
			continue
		}

		name, ok := propertyName(keyed.Key)
		if !ok {
			continue
		}

		switch strings.ToLower(name) {
		case "url":
			if value, ok := e.resolveString(keyed.Value); ok {
				path = value
			}

		case "method":
			if value, ok := e.resolveString(keyed.Value); ok {
				method = strings.ToUpper(strings.TrimSpace(value))
			}
		}
	}

	if path == "" {
		return true
	}

	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
	default:
		return true
	}

	appendJSEndpoint(
		&e.endpoints,
		e.seen,
		method,
		path,
		"axios-config-ast",
	)

	return true
}

func joinJSURL(baseURL, path string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	path = strings.TrimSpace(path)

	if path == "" {
		return baseURL
	}

	if strings.HasPrefix(path, "http://") ||
		strings.HasPrefix(path, "https://") ||
		strings.HasPrefix(path, "ws://") ||
		strings.HasPrefix(path, "wss://") {
		return path
	}

	return baseURL + "/" + strings.TrimLeft(path, "/")
}

func (e *endpointASTExtractor) handleXHRCall(
	call *ast.CallExpression,

) bool {
	callee, ok := call.Callee.(*ast.DotExpression)
	if !ok {
		return false
	}

	if !strings.EqualFold(callee.Identifier.Name.String(), "open") {
		return false
	}

	if len(call.ArgumentList) < 2 {
		return true
	}

	method, ok := e.resolveString(call.ArgumentList[0])
	if !ok {
		return true
	}

	path, ok := e.resolveString(call.ArgumentList[1])
	if !ok {
		return true
	}

	method = strings.ToUpper(strings.TrimSpace(method))

	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
	default:
		return true
	}

	appendJSEndpoint(
		&e.endpoints,
		e.seen,
		method,
		path,
		"xhr-ast",
	)

	return true
}

func (e *endpointASTExtractor) fetchMethod(
	expression ast.Expression,
) (string, bool) {
	object, ok := expression.(*ast.ObjectLiteral)
	if !ok {
		return "", false
	}

	for _, property := range object.Value {
		keyed, ok := property.(*ast.PropertyKeyed)
		if !ok {
			continue
		}

		key, ok := propertyName(keyed.Key)
		if !ok || !strings.EqualFold(key, "method") {
			continue
		}

		method, ok := e.resolveString(keyed.Value)
		if !ok {
			return "", false
		}

		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			return "", false
		}

		return method, true
	}

	return "", false
}

func propertyName(expression ast.Expression) (string, bool) {
	switch node := expression.(type) {
	case *ast.Identifier:
		return node.Name.String(), true

	case *ast.StringLiteral:
		return node.Value.String(), true

	default:
		return "", false
	}
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
