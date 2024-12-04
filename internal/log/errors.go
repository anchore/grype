package log

import "io"

func CloseAndLogError(closer io.Closer, location string) {
	if closer == nil {
		Debug("no closer provided when attempting to close: %v", location)
		return
	}
	err := closer.Close()
	if err != nil {
		Debug("failed to close file: %v due to: %v", location, err)
	}
}
