package event

import (
	"github.com/wagoodman/go-partybus"
)

const (
	typePrefix    = "grype"
	cliTypePrefix = typePrefix + "-cli"

	// Events from the grype library

	UpdateVulnerabilityDatabase  partybus.EventType = typePrefix + "-update-vulnerability-database"
	VulnerabilityScanningStarted partybus.EventType = typePrefix + "-vulnerability-scanning-started"
	DatabaseDiffingStarted       partybus.EventType = typePrefix + "-database-diffing-started"

	// Events exclusively for the CLI

	// CLIAppUpdateAvailable is a partybus event that occurs when an application update is available
	CLIAppUpdateAvailable partybus.EventType = cliTypePrefix + "-app-update-available"

	// CLIReport is a partybus event that occurs when an analysis result is ready for final presentation to stdout
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLINotification is a partybus event that occurs when auxiliary information is ready for presentation to stderr
	CLINotification partybus.EventType = cliTypePrefix + "-notification"
)
