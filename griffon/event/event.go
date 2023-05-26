package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable            partybus.EventType = "griffon-app-update-available"
	UpdateVulnerabilityDatabase   partybus.EventType = "griffon-update-vulnerability-database"
	VulnerabilityScanningStarted  partybus.EventType = "griffon-vulnerability-scanning-started"
	VulnerabilityScanningFinished partybus.EventType = "griffon-vulnerability-scanning-finished"
	NonRootCommandFinished        partybus.EventType = "griffon-non-root-command-finished"
	DatabaseDiffingStarted        partybus.EventType = "griffon-database-diffing-started"
)
