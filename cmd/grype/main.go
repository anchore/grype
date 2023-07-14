package main

import (
	"github.com/anchore/grype/cmd/grype/cli/legacy"
)

func main() {
	cli := legacy.NewCli()
	cli.Execute()
}
