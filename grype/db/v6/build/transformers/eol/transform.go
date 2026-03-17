package eol

import (
	"strconv"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/internal/log"
)

// productNameMapping translates endoflife.date product names to grype distro names.
// Only includes mappings where the names differ.
var productNameMapping = map[string]string{
	"alpine-linux":  "alpine",
	"rhel":          "redhat",
	"amazon-linux":  "amazonlinux",
	"oracle-linux":  "oraclelinux",
	"rocky-linux":   "rockylinux",
	"centos-stream": "centos", // CentOS Stream is separate from classic CentOS
}

// supportedDistros lists distros we want to import EOL data for.
// These are distros that grype tracks vulnerability data for.
var supportedDistros = map[string]bool{
	"alpine":      true,
	"amazonlinux": true,
	"centos":      true,
	"debian":      true,
	"fedora":      true,
	"oraclelinux": true,
	"redhat":      true,
	"rockylinux":  true,
	"almalinux":   true,
	"sles":        true,
	"ubuntu":      true,
	"photon":      true,
	"mariner":     true,
	"azurelinux":  true,
	"wolfi":       true,
	"chainguard":  true,
}

// Transform converts an EOL record into entries for the database.
func Transform(entry unmarshal.EndOfLifeDateRelease, state provider.State) ([]data.Entry, error) {
	productName := entry.ProductName()
	distroName := translateProductName(productName)

	// Skip non-distro products (software packages, frameworks, etc.)
	if !supportedDistros[distroName] {
		log.WithFields("product", productName).Trace("skipping non-distro EOL record")
		return nil, nil
	}

	handle := getOperatingSystemEOL(entry, distroName)
	if handle == nil {
		return nil, nil
	}

	return transformers.NewEntries(*provider.Model(state), *handle), nil
}

// translateProductName converts endoflife.date product names to grype distro names.
func translateProductName(product string) string {
	if mapped, ok := productNameMapping[product]; ok {
		return mapped
	}
	return product
}

// getOperatingSystemEOL creates an OperatingSystemEOLHandle from an EOL record.
func getOperatingSystemEOL(entry unmarshal.EndOfLifeDateRelease, distroName string) *db.OperatingSystemEOLHandle {
	// Parse version from name (e.g., "12", "22.04", "8.5")
	majorVersion, minorVersion := parseVersion(entry.Name)

	// Parse EOL dates
	var eolDate, eoasDate *time.Time
	if entry.EOLFrom != nil {
		eolDate = internal.ParseTime(*entry.EOLFrom)
	}
	if entry.EOASFrom != nil {
		eoasDate = internal.ParseTime(*entry.EOASFrom)
	}

	// Skip if no EOL data
	if eolDate == nil && eoasDate == nil {
		return nil
	}

	// Note: We intentionally don't include codename in the handle because
	// endoflife.date uses full names like "Noble Numbat" while the DB uses
	// short lowercase names like "noble". Version matching is sufficient.
	return &db.OperatingSystemEOLHandle{
		Name:         distroName,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		EOLDate:      eolDate,
		EOASDate:     eoasDate,
	}
}

// parseVersion extracts major and minor version from a cycle string.
// Normalizes versions by stripping leading zeros (e.g., "04" -> "4")
// to match the format used in the vulnerability database.
func parseVersion(cycle string) (major, minor string) {
	parts := strings.Split(cycle, ".")
	if len(parts) >= 1 {
		major = normalizeVersion(parts[0])
	}
	if len(parts) >= 2 {
		minor = normalizeVersion(parts[1])
	}
	return major, minor
}

// normalizeVersion strips leading zeros from a version string.
func normalizeVersion(v string) string {
	// Try to parse as integer to strip leading zeros
	if i, err := strconv.Atoi(v); err == nil {
		return strconv.Itoa(i)
	}
	return v
}
