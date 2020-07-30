package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable               partybus.EventType = "grype-app-update-available"
	DownloadingVulnerabilityDatabase partybus.EventType = "grype-downloading-vulnerability-database"
	VulnerabilityScanningStarted     partybus.EventType = "grype-vulnerability-scanning-started"
	VulnerabilityScanningFinished    partybus.EventType = "grype-vulnerability-scanning-finished"
)
