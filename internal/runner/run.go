package runner

import (
	"fmt"
	"os"
	"os/exec"
)

func ConfirmAndRun(args []string, auto bool) error {

	if !auto {
		fmt.Print("\nExecute request? (y/n): ")

		var input string
		fmt.Scanln(&input)

		if input != "y" && input != "Y" {
			fmt.Println("aborted.")
			return nil
		}
	}

	cmd := exec.Command("curl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}
