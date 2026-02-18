package builder

import (
	"cwrap/internal/model"
)

type Result struct {
	Args    []string
	Cmd     string
	Headers []model.Header
}

func Build(req model.Request) Result {

	finalURL := applyQuery(req.URL, req.Flags.Query)

	args := buildMethod(req)
	args = buildBody(args, req)
	args = append(args, finalURL)
	args = buildMultipart(args, req)

	headers := buildHeaders(req)
	args = appendHeaderArgs(args, headers)

	args = buildOptions(args, req, headers)

	return Result{
		Args:    args,
		Cmd:     buildString(args),
		Headers: headers,
	}
}
