package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

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

	value := nodeText(argument, source)

	if property != "" {
		value += "." + property
	}

	return value
}

func mergeDataFlowCallValues(
	base dataFlowCallValues,
	extra dataFlowCallValues,
) dataFlowCallValues {
	result := newDataFlowCallValues()

	for name, value := range base.Scalars {
		result.Scalars[name] = value
	}

	for name, properties := range base.Objects {
		copied := make(map[string]string)

		for property, value := range properties {
			copied[property] = value
		}

		result.Objects[name] = copied
	}

	for name, value := range extra.Scalars {
		result.Scalars[name] = value
	}

	for name, properties := range extra.Objects {
		if result.Objects[name] == nil {
			result.Objects[name] = make(map[string]string)
		}

		for property, value := range properties {
			result.Objects[name][property] = value
		}
	}

	return result
}
