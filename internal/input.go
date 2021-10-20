package internal

import (
	"fmt"
	"os"
)

// IsPipedInput returns true if there is no input device, which means the user **may** be providing input via a pipe.
func IsPipedInput() (bool, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false, fmt.Errorf("unable to determine if there is piped input: %w", err)
	}

	return fi.Mode()&os.ModeCharDevice == 0, nil
}
