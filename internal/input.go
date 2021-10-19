package internal

import "os"

// IsPipedInput returns true if there is no input device, which means the user **may** be providing input via a pipe.
func IsPipedInput() bool {
	fi, _ := os.Stdin.Stat()

	return fi.Mode()&os.ModeCharDevice == 0
}
