package runner

import (
	"cwrap/internal/curl"
	"cwrap/internal/logger"
	"cwrap/internal/model"
	"fmt"
	"os"
	"os/exec"
)

type CurlExecutor struct{}

func (CurlExecutor) Run(req model.Request) error {
	if _, err := exec.LookPath("curl"); err != nil {
		return fmt.Errorf("curl is required for %s but was not found in PATH(please manually install curl)", req.Original)
	}
	result := curl.Build(req)
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

	if err := cmd.Run(); err != nil {
		return err
	}

	// sync curl's cookie jar into the cwrap session store so recon
	// can pick up the session automatically on the next run
	if req.Flags.AutoCookie {
		if err := curl.SyncJarToSession(req.URL); err != nil {
			fmt.Fprintf(os.Stderr, "\ncwrap: warning: failed to sync cookies to session store: %v\n", err)
		}
	}

	return nil
}
