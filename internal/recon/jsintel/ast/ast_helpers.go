package astp

import (
	"strings"

	"github.com/dop251/goja/ast"
)

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
