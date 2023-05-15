package internal

import (
	"fmt"
	"os"
)

// IsStdinPipeOrRedirect returns true if stdin is provided via pipe or redirect
func IsStdinPipeOrRedirect() (bool, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false, fmt.Errorf("unable to determine if there is piped input: %w", err)
	}

	// note: we should NOT use the absence of a character device here as the hint that there may be input expected
	// on stdin, as running grype as a subprocess you would expect no character device to be present but input can
	// be from either stdin or indicated by the CLI. Checking if stdin is a pipe is the most direct way to determine
	// if there *may* be bytes that will show up on stdin that should be used for the analysis source.
	return fi.Mode()&os.ModeNamedPipe != 0 || fi.Size() > 0, nil
}
