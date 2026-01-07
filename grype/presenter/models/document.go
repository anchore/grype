package models

import (
	"fmt"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Document represents the JSON document to be presented
type Document struct {
	Matches         []Match         `json:"matches"`
	IgnoredMatches  []IgnoredMatch  `json:"ignoredMatches,omitempty"`
	AlertsByPackage []PackageAlerts `json:"alertsByPackage,omitempty"`
	Source          *source         `json:"source"`
	Distro          distribution    `json:"distro"`
	Descriptor      descriptor      `json:"descriptor"`
}

// NewDocument creates and populates a new Document struct, representing the populated JSON document.
//
//nolint:staticcheck // MetadataProvider is deprecated but still used internally
func NewDocument(id clio.Identification, packages []pkg.Package, context pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch, metadataProvider vulnerability.MetadataProvider, appConfig any, dbInfo any, strategy SortStrategy, outputTimestamp bool, distroAlerts *DistroAlertData) (Document, error) {
	var timestamp []byte

	if !outputTimestamp {
		// can't be nil in string() call
		timestamp = []byte{}
	} else {
		var timestampErr error
		timestamp, timestampErr = time.Now().Local().MarshalText()
		if timestampErr != nil {
			return Document{}, timestampErr
		}
	}

	// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
	var findings = make([]Match, 0)
	for _, m := range matches.Sorted() {
		p := pkg.ByID(m.Package.ID, packages)
		if p == nil {
			return Document{}, fmt.Errorf("unable to find package in collection: %+v", p)
		}

		matchModel, err := newMatch(m, *p, metadataProvider)
		if err != nil {
			return Document{}, err
		}

		findings = append(findings, *matchModel)
	}

	SortMatches(findings, strategy)

	var src *source
	if context.Source != nil {
		theSrc, err := newSource(*context.Source)
		if err != nil {
			return Document{}, err
		}
		src = &theSrc
	}

	var ignoredMatchModels []IgnoredMatch
	for _, m := range ignoredMatches {
		p := pkg.ByID(m.Package.ID, packages)
		if p == nil {
			return Document{}, fmt.Errorf("unable to find package in collection: %+v", p)
		}

		matchModel, err := newMatch(m.Match, *p, metadataProvider)
		if err != nil {
			return Document{}, err
		}

		ignoredMatch := IgnoredMatch{
			Match:              *matchModel,
			AppliedIgnoreRules: mapIgnoreRules(m.AppliedIgnoreRules),
		}
		ignoredMatchModels = append(ignoredMatchModels, ignoredMatch)
	}

	return Document{
		Matches:         findings,
		IgnoredMatches:  ignoredMatchModels,
		AlertsByPackage: buildPackageAlerts(distroAlerts),
		Source:          src,
		Distro:          newDistribution(context, selectMostCommonDistro(packages)),
		Descriptor: descriptor{
			Name:          id.Name,
			Version:       id.Version,
			Configuration: appConfig,
			DB:            dbInfo,
			Timestamp:     string(timestamp),
		},
	}, nil
}

// buildPackageAlerts creates PackageAlerts from distro tracking data.
func buildPackageAlerts(data *DistroAlertData) []PackageAlerts {
	if data == nil {
		return nil
	}

	// map package ID to alerts for deduplication
	alertsByPkg := make(map[string]*PackageAlerts)

	// helper to add an alert for a package
	addAlert := func(p pkg.Package, alertType AlertType, message string, metadata any) {
		pkgID := string(p.ID)
		alert := Alert{
			Type:     alertType,
			Message:  message,
			Metadata: metadata,
		}
		if existing, ok := alertsByPkg[pkgID]; ok {
			existing.Alerts = append(existing.Alerts, alert)
		} else {
			alertsByPkg[pkgID] = &PackageAlerts{
				Package: newPackage(p),
				Alerts:  []Alert{alert},
			}
		}
	}

	// helper to extract distro metadata
	distroMetadata := func(p pkg.Package) DistroAlertMetadata {
		if p.Distro != nil {
			return DistroAlertMetadata{
				Name:    p.Distro.Name(),
				Version: p.Distro.VersionString(),
			}
		}
		return DistroAlertMetadata{Name: "unknown"}
	}

	// add alerts for disabled distro packages
	for _, p := range data.DisabledDistroPackages {
		distroName := "unknown"
		if p.Distro != nil {
			distroName = p.Distro.String()
		}
		addAlert(p, AlertTypeDistroDisabled, fmt.Sprintf("Package is from %s which is disabled for vulnerability matching", distroName), distroMetadata(p))
	}

	// add alerts for unknown distro packages
	for _, p := range data.UnknownDistroPackages {
		distroName := "unknown"
		if p.Distro != nil {
			distroName = p.Distro.String()
		}
		addAlert(p, AlertTypeDistroUnknown, fmt.Sprintf("Package is from unrecognized distro: %s", distroName), distroMetadata(p))
	}

	// add alerts for EOL distro packages
	for _, p := range data.EOLDistroPackages {
		distroName := "unknown"
		if p.Distro != nil {
			distroName = p.Distro.String()
		}
		addAlert(p, AlertTypeDistroEOL, fmt.Sprintf("Package is from end-of-life distro: %s", distroName), distroMetadata(p))
	}

	// convert map to slice
	if len(alertsByPkg) == 0 {
		return nil
	}

	result := make([]PackageAlerts, 0, len(alertsByPkg))
	for _, pa := range alertsByPkg {
		result = append(result, *pa)
	}

	return result
}

// selectMostCommonDistro selects the most common distro from the provided packages.
func selectMostCommonDistro(pkgs []pkg.Package) *distro.Distro {
	distros := make(map[string]*distro.Distro)
	count := make(map[string]int)

	var maxDistro *distro.Distro
	maxCount := 0

	for _, p := range pkgs {
		if p.Distro != nil {
			s := p.Distro.String()
			count[s]++

			if _, ok := distros[s]; !ok {
				distros[s] = p.Distro
			}

			if count[s] > maxCount {
				maxCount = count[s]
				maxDistro = p.Distro
			}
		}
	}

	return maxDistro
}
