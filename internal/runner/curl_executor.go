package runner

import (
	"cwrap/internal/builder"
	"cwrap/internal/logger"
	"cwrap/internal/model"
	"fmt"
	"os"
	"os/exec"
)

type CurlExecutor struct{}

func (CurlExecutor) Run(req model.Request) error {

	result := builder.Build(req)
	logger.PrintCommand(req, result)

	if !req.Flags.Run {
		fmt.Print("\nExecute request? (y/n): ")

		var input string
		fmt.Scanln(&input)

		if input != "y" && input != "Y" {
			fmt.Println("aborted.")
			return nil
		}
	}

	cmd := exec.Command("curl", result.Args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}
