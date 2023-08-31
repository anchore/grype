package main

import (
	"os"

	"github.com/anchore/grype/cmd/grype/cli/legacy"
	"github.com/anchore/grype/internal/log"
)

func main() {
	cli := legacy.NewCli()
	err := cli.Execute()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
