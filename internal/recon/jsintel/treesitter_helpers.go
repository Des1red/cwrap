package jsintel

import (
	"fmt"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

func parseJavaScriptTree(source []byte) (*tree_sitter.Tree, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()

	language := tree_sitter.NewLanguage(
		tree_sitter_javascript.Language(),
	)

	if err := parser.SetLanguage(language); err != nil {
		return nil, fmt.Errorf("set JavaScript grammar: %w", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, fmt.Errorf("tree-sitter returned nil tree")
	}

	return tree, nil
}

type javaScriptScope struct {
	Kind   string
	Start  uint
	End    uint
	Source string
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

func isHTTPCallNode(
	call *tree_sitter.Node,
	source []byte,
	axiosClients map[string]bool,
) bool {
	if call == nil {
		return false
	}

	function := call.ChildByFieldName("function")
	if function == nil {
		return false
	}

	name := strings.TrimSpace(function.Utf8Text(source))
	lower := strings.ToLower(name)

	if isFetchCall(function, source) {
		return true
	}

	if lower == "axios" {
		return true
	}

	if strings.HasPrefix(lower, "axios.") {
		switch strings.TrimPrefix(lower, "axios.") {
		case "get", "post", "put", "delete", "patch", "options", "head":
			return true
		}
	}

	if function.Kind() == "member_expression" {
		object := function.ChildByFieldName("object")
		property := function.ChildByFieldName("property")

		if object != nil && property != nil {
			clientName := strings.TrimSpace(object.Utf8Text(source))
			method := strings.ToLower(
				strings.TrimSpace(property.Utf8Text(source)),
			)

			if axiosClients[clientName] {
				switch method {
				case "get", "post", "put", "delete",
					"patch", "options", "head":
					return true
				}
			}
		}
	}

	if strings.HasSuffix(lower, ".open") {
		return isXHRLikeOpenCall(call, source)
	}

	return false
}

func isFetchCall(
	function *tree_sitter.Node,
	source []byte,
) bool {
	if function == nil {
		return false
	}

	if function.Kind() == "identifier" {
		return strings.TrimSpace(
			function.Utf8Text(source),
		) == "fetch"
	}

	if function.Kind() != "member_expression" {
		return false
	}

	property := function.ChildByFieldName("property")
	if property == nil {
		return false
	}

	return strings.TrimSpace(
		property.Utf8Text(source),
	) == "fetch"
}

func isXHRLikeOpenCall(
	call *tree_sitter.Node,
	source []byte,
) bool {
	arguments := call.ChildByFieldName("arguments")
	if arguments == nil || arguments.NamedChildCount() < 2 {
		return false
	}

	methodNode := arguments.NamedChild(0)
	if methodNode == nil {
		return false
	}

	method := strings.TrimSpace(methodNode.Utf8Text(source))
	method = strings.Trim(method, `"'`)

	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
		return true
	default:
		return false
	}
}
func nearestJavaScriptScope(
	node *tree_sitter.Node,
) *tree_sitter.Node {
	for current := node; current != nil; current = current.Parent() {
		switch current.Kind() {
		case "function_declaration",
			"function_expression",
			"arrow_function":
			return current
		}
	}

	return nil
}

func extractEndpointsFromTreeScopes(
	scopes []javaScriptScope,
) ([]JSEndpoint, int, int) {
	endpoints := make([]JSEndpoint, 0)
	seen := make(map[string]bool)
	parsedScopes := 0
	failedScopes := 0

	for _, scope := range scopes {
		scopeSource := prepareScopeForGoja(scope)

		resolved, parseErr := parseEndpointProgram(scopeSource)
		if parseErr != nil {
			failedScopes++
			continue
		}

		parsedScopes++

		for _, endpoint := range resolved {
			appendJSEndpoint(
				&endpoints,
				seen,
				endpoint.Method,
				endpoint.Path,
				endpoint.Kind,
			)
		}
	}

	return endpoints, parsedScopes, failedScopes
}

func prepareScopeForGoja(scope javaScriptScope) string {
	switch scope.Kind {
	case "function_expression",
		"arrow_function":
		return "(" + scope.Source + ");"

	default:
		return scope.Source
	}
}

func treeStringLiteral(
	node *tree_sitter.Node,
	source []byte,
) (string, bool) {
	if node == nil || node.Kind() != "string" {
		return "", false
	}

	raw := strings.TrimSpace(node.Utf8Text(source))
	if len(raw) < 2 {
		return "", false
	}

	quote := raw[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	if raw[len(raw)-1] != quote {
		return "", false
	}

	return raw[1 : len(raw)-1], true
}

func collectDataFlowParameters(
	parametersNode *tree_sitter.Node,
	source []byte,
) []string {
	parameters := make([]string, 0)

	if parametersNode == nil {
		return parameters
	}

	for index := uint(0); index < parametersNode.NamedChildCount(); index++ {

		parameter := parametersNode.NamedChild(index)
		if parameter == nil ||
			parameter.Kind() != "identifier" {
			continue
		}

		parameters = append(
			parameters,
			strings.TrimSpace(parameter.Utf8Text(source)),
		)
	}

	return parameters
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func buildDataFlowFunction(
	parametersNode *tree_sitter.Node,
	bodyNode *tree_sitter.Node,
	source []byte,
) dataFlowFunction {
	parameters := collectDataFlowParameters(
		parametersNode,
		source,
	)

	result := findFetchDataFlowParameters(
		bodyNode,
		source,
		parameters,
	)

	result.Parameters = parameters

	return result
}

func addConditionalMethods(
	value *tree_sitter.Node,
	source []byte,
	methods *[]string,
) {
	consequence := value.ChildByFieldName("consequence")
	alternative := value.ChildByFieldName("alternative")

	for _, candidate := range []*tree_sitter.Node{
		consequence,
		alternative,
	} {
		method, ok := treeStringLiteral(candidate, source)
		if !ok {
			continue
		}

		method = strings.ToUpper(method)

		if !containsString(*methods, method) {
			*methods = append(*methods, method)
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

func mapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))

	for key := range values {
		keys = append(keys, key)
	}

	return keys
}

func dataFlowArgumentSource(
	target dataFlowFunction,
	arguments *tree_sitter.Node,
	source []byte,
	parameter string,
	property string,
) string {
	if parameter == "" {
		return ""
	}

	index := -1

	for position, name := range target.Parameters {
		if name == parameter {
			index = position
			break
		}
	}

	if index < 0 ||
		arguments == nil ||
		uint(index) >= arguments.NamedChildCount() {
		if property != "" {
			return parameter + "." + property
		}

		return parameter
	}

	argument := arguments.NamedChild(uint(index))
	if argument == nil {
		return ""
	}

	value := strings.TrimSpace(
		argument.Utf8Text(source),
	)

	if property != "" {
		value += "." + property
	}

	return value
}

func dataFlowURLSource(
	target dataFlowFunction,
	arguments *tree_sitter.Node,
	source []byte,
) string {
	if target.FetchStaticPath != "" {
		return target.FetchStaticPath
	}

	if target.RequestURLParam != "" {
		return dataFlowArgumentSource(
			target,
			arguments,
			source,
			target.RequestURLParam,
			target.RequestURLProperty,
		)
	}

	return dataFlowArgumentSource(
		target,
		arguments,
		source,
		target.FetchURLParam,
		target.FetchURLProperty,
	)
}

func dataFlowMethodSource(
	target dataFlowFunction,
	arguments *tree_sitter.Node,
	source []byte,
) string {
	if len(target.FetchMethods) > 0 {
		return strings.Join(target.FetchMethods, "|")
	}

	if target.RequestMethodParam != "" {
		return dataFlowArgumentSource(
			target,
			arguments,
			source,
			target.RequestMethodParam,
			target.RequestMethodProperty,
		)
	}

	return dataFlowArgumentSource(
		target,
		arguments,
		source,
		target.FetchMethodParam,
		target.FetchMethodProperty,
	)
}

func normalizeHTTPMethod(value string) (string, bool) {
	method := strings.ToUpper(
		strings.TrimSpace(value),
	)

	switch method {
	case "GET", "POST", "PUT", "DELETE",
		"PATCH", "OPTIONS", "HEAD":
		return method, true
	default:
		return "", false
	}
}

func validHTTPMethods(values []string) []string {
	methods := make([]string, 0, len(values))

	for _, value := range values {
		method, ok := normalizeHTTPMethod(value)
		if !ok || containsString(methods, method) {
			continue
		}

		methods = append(methods, method)
	}

	return methods
}
