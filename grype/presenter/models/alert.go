package models

import (
	"github.com/anchore/grype/grype/pkg"
)

// AlertType represents categories of non-vulnerability concerns
type AlertType string

const (
	// AlertTypeDistroEOL indicates a package is from an end-of-life distro
	AlertTypeDistroEOL AlertType = "distro-eol"

	// AlertTypeDistroUnknown indicates a package is from an unrecognized distro
	AlertTypeDistroUnknown AlertType = "distro-unknown"

	// AlertTypeDistroDisabled indicates a package is from a distro that is disabled for matching
	AlertTypeDistroDisabled AlertType = "distro-disabled"
)

// Alert represents a non-vulnerability concern for a package
type Alert struct {
	Type    AlertType   `json:"type"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// PackageAlerts groups alerts for a specific package
type PackageAlerts struct {
	Package Package `json:"package"`
	Alerts  []Alert `json:"alerts"`
}

// DistroAlertData holds packages that should generate distro-related alerts.
// This data is typically collected during vulnerability matching and passed
// to NewDocument for alert generation.
type DistroAlertData struct {
	// DisabledDistroPackages are packages from distros that are disabled for matching (e.g., Arch Linux)
	DisabledDistroPackages []pkg.Package

	// UnknownDistroPackages are packages from unrecognized distros
	UnknownDistroPackages []pkg.Package

	// EOLDistroPackages are packages from distros that have reached end-of-life
	EOLDistroPackages []pkg.Package
}
