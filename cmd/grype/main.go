package main

import (
	_ "github.com/glebarez/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli"
	"github.com/anchore/grype/cmd/grype/internal"
)

// applicationName is the non-capitalized name of the application (do not change this)
const applicationName = "grype"

// all variables here are provided as build-time arguments, with clear default values
var (
	version        = internal.NotProvided
	buildDate      = internal.NotProvided
	gitCommit      = internal.NotProvided
	gitDescription = internal.NotProvided
)

func main() {
	app := cli.Application(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	app.Run()
}
