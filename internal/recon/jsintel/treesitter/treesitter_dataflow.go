package treesitter

import (
	"cwrap/internal/recon/jsintel/common"
	"fmt"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

type dataFlowFunction struct {
	Parameters []string
	Sink       string

	FetchURLParam         string
	FetchMethodParam      string
	FetchURLProperty      string
	FetchMethodProperty   string
	FetchMethods          []string
	FetchStaticPath       string
	RequestURLParam       string
	RequestURLProperty    string
	RequestMethodParam    string
	RequestMethodProperty string
}
type JSHTTPFlow struct {
	Function string
	Sink     string

	URLSource    string
	MethodSource string

	ResolvedURL    string
	ResolvedMethod string

	DynamicURL    bool
	DynamicMethod bool

	Confidence string
}

type dataFlowExtractionResult struct {
	Endpoints []common.JSEndpoint
	HTTPFlows []JSHTTPFlow
}

type dataFlowBinding struct {
	Target dataFlowFunction
	Values dataFlowCallValues
}

type dataFlowMutator struct {
	Parameters      []string
	FieldParameters map[string]string
}

type dataFlowInstance struct {
	ClassName    string
	Fields       map[string]string
	ObjectFields map[string]dataFlowInstance
}
type dataFlowClass struct {
	ConstructorParameters []string
	FieldParameters       map[string]string
	Methods               map[string]dataFlowFunction
	Mutators              map[string]dataFlowMutator
}

type dataFlowCallValues struct {
	Scalars map[string]string
	Objects map[string]map[string]string
}

func newDataFlowCallValues() dataFlowCallValues {
	return dataFlowCallValues{
		Scalars: make(map[string]string),
		Objects: make(map[string]map[string]string),
	}
}

func newDataFlowClass() dataFlowClass {
	return dataFlowClass{
		FieldParameters: make(map[string]string),
		Methods:         make(map[string]dataFlowFunction),
		Mutators:        make(map[string]dataFlowMutator),
	}
}

func extractEndpointsDataFlow(
	source []byte,
) (dataFlowExtractionResult, error) {
	tree, err := parseJavaScriptTree(source)
	if err != nil {
		return dataFlowExtractionResult{},
			fmt.Errorf("parse JavaScript tree: %w", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		return dataFlowExtractionResult{},
			fmt.Errorf("tree-sitter returned nil root node")
	}
	stringValues := findStringVariables(root, source)

	bindings := findDataFlowBindings(
		root,
		source,
		stringValues,
	)
	endpoints := make([]common.JSEndpoint, 0)
	flows := make([]JSHTTPFlow, 0)
	seen := make(map[string]bool)
	seenFlows := make(map[string]bool)

	walkTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "call_expression" {
			return
		}

		functionNode := node.ChildByFieldName("function")
		argumentsNode := node.ChildByFieldName("arguments")

		if functionNode == nil || argumentsNode == nil {
			return
		}

		functionName := nodeText(functionNode, source)

		binding, exists := bindings[functionName]
		if !exists {
			return
		}

		callValues := resolveDataFlowCallValues(
			binding.Target,
			argumentsNode,
			source,
			stringValues,
		)

		values := mergeDataFlowCallValues(
			binding.Values,
			callValues,
		)

		path, kind, pathResolved := resolveDataFlowPath(
			binding.Target,
			values,
		)

		methods := resolveDataFlowMethods(
			binding.Target,
			values,
		)

		methodResolved := isDataFlowMethodResolved(
			binding.Target,
			values,
		)

		if !pathResolved || !methodResolved {
			urlSource := dataFlowURLSource(
				binding.Target,
				argumentsNode,
				source,
			)

			methodSource := dataFlowMethodSource(
				binding.Target,
				argumentsNode,
				source,
			)

			flow := JSHTTPFlow{
				Function:      functionName,
				Sink:          binding.Target.Sink,
				URLSource:     urlSource,
				MethodSource:  methodSource,
				DynamicURL:    !pathResolved,
				DynamicMethod: !methodResolved,
				Confidence:    "medium",
			}

			if pathResolved {
				flow.ResolvedURL = path
			}

			if methodResolved && len(methods) == 1 {
				if method, ok :=
					normalizeHTTPMethod(methods[0]); ok {

					flow.ResolvedMethod = method
				}
			}

			key := fmt.Sprintf(
				"%s|%s|%s|%s|%s|%s|%t|%t",
				flow.Function,
				flow.Sink,
				flow.URLSource,
				flow.MethodSource,
				flow.ResolvedURL,
				flow.ResolvedMethod,
				flow.DynamicURL,
				flow.DynamicMethod,
			)

			if !seenFlows[key] {
				seenFlows[key] = true
				flows = append(flows, flow)
			}

			return
		}

		for _, method := range methods {
			common.AppendJSEndpoint(
				&endpoints,
				seen,
				method,
				path,
				kind,
			)
		}
	})

	return dataFlowExtractionResult{
		Endpoints: endpoints,
		HTTPFlows: flows,
	}, nil
}
