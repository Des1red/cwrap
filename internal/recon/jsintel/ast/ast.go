package astp

import (
	"fmt"

	"cwrap/internal/recon/jsintel/common"

	"github.com/dop251/goja/parser"
)

type endpointASTExtractor struct {
	constants    map[string]string
	objectValues map[string]map[string]string
	axiosClients map[string]string

	endpoints []common.JSEndpoint
	seen      map[string]bool
}

func ExtractEndpointsAST(source string) ([]common.JSEndpoint, error) {
	return parseEndpointProgram(source)
}

func parseEndpointProgram(source string) ([]common.JSEndpoint, error) {
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
