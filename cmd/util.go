package cmd

import (
	"fmt"
	"os"
	"strings"
)

func stderrPrintLnf(message string, args ...interface{}) error {
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	_, err := fmt.Fprintf(os.Stderr, message, args...)
	return err
}
