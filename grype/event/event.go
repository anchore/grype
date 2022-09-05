package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable             partybus.EventType = "grype-app-update-available"
	UpdateVulnerabilityDatabase    partybus.EventType = "grype-update-vulnerability-database"
	VulnerabilityScanningStarted   partybus.EventType = "grype-vulnerability-scanning-started"
	VulnerabilityScanningFinished  partybus.EventType = "grype-vulnerability-scanning-finished"
	AttestationVerified            partybus.EventType = "grype-attestation-signature-passed"
	AttestationVerificationSkipped partybus.EventType = "grype-attestation-verification-skipped"
	NonRootCommandFinished         partybus.EventType = "grype-non-root-command-finished"
	DatabaseDiffingStarted         partybus.EventType = "grype-database-diffing-started"
	GrypeUpdate                    partybus.EventType = "grype-grype-update-started"
)
