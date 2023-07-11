package event

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/internal"
)

const (
	typePrefix    = internal.ApplicationName
	cliTypePrefix = typePrefix + "-cli"

	UpdateVulnerabilityDatabase  partybus.EventType = "grype-update-vulnerability-database"
	VulnerabilityScanningStarted partybus.EventType = "grype-vulnerability-scanning-started"
	DatabaseDiffingStarted       partybus.EventType = "grype-database-diffing-started"

	// Events exclusively for the CLI

	// CLIAppUpdateAvailable is a partybus event that occurs when an application update is available
	CLIAppUpdateAvailable partybus.EventType = cliTypePrefix + "-app-update-available"

	// CLIReport is a partybus event that occurs when an analysis result is ready for final presentation to stdout
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLIExit is a partybus event that occurs when an analysis result is ready for final presentation
	CLIExit partybus.EventType = cliTypePrefix + "-exit-event"
)
