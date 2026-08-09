package astp

import (
	"cwrap/internal/recon/jsintel/common"
	"strings"

	"github.com/dop251/goja/ast"
)

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

	common.AppendJSEndpoint(
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

	common.AppendJSEndpoint(
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

	common.AppendJSEndpoint(
		&e.endpoints,
		e.seen,
		method,
		path,
		"axios-config-ast",
	)

	return true
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

	common.AppendJSEndpoint(
		&e.endpoints,
		e.seen,
		method,
		path,
		"xhr-ast",
	)

	return true
}
