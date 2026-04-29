package cmd

import (
	"cwrap/internal/flags"
	"cwrap/internal/intent"
	"cwrap/internal/runner"
	"fmt"
	"os"
)

func Execute() {

	boot()
	manFlags()

	req := intent.Parse(os.Args)
	handler := intent.Resolve(req)

	offset := 2
	if req.URL != "" || req.FilePath != "" {
		offset = 3
	}

	args := os.Args[offset:]
	if handler != nil {
		args = handler.Translate(args)
	}

	// parse flags after method + url
	req.Flags = flags.Parse(args)
	if handler != nil {
		handler.ApplyDefaults(&req, &req.Flags)
	}

	if err := runner.Execute(req); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

}
