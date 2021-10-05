package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func reportWriter() (io.Writer, func() error, error) {
	nop := func() error { return nil }

	path := strings.TrimSpace(appConfig.File)
	switch len(path) {
	case 0:
		return os.Stdout, nop, nil
	default:
		reportFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return nil, nop, fmt.Errorf("unable to create report file: %w", err)
		}
		return reportFile, func() error {
			if !appConfig.Quiet {
				fmt.Printf("Report written to %q\n", path)
			}
			return reportFile.Close()
		}, nil
	}
}
