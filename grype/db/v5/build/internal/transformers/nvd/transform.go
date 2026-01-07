package nvd

import (
	"slices"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/build/internal/transformers"
	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/platformcpe"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/syft/syft/cpe"
)

type Config struct {
	CPEParts            *strset.Set
	InferNVDFixVersions bool
}

func defaultConfig() Config {
	return Config{
		CPEParts:            strset.New("a"),
		InferNVDFixVersions: true,
	}
}

func Transformer(cfg Config) data.NVDTransformer {
	if cfg == (Config{}) {
		cfg = defaultConfig()
	}
	return func(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
		return transform(cfg, vulnerability)
	}
}

func transform(cfg Config, vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	// TODO: stop capturing record source in the vulnerability metadata record (now that feed groups are not real)
	recordSource := "nvdv2:nvdv2:cves"

	grypeNamespace, err := namespace.FromString("nvd:cpe")
	if err != nil {
		return nil, err
	}

	entryNamespace := grypeNamespace.String()

	uniquePkgs := findUniquePkgs(cfg, vulnerability.Configurations...)

	// extract all links
	var links []string
	for _, externalRefs := range vulnerability.References {
		// TODO: should we capture other information here?
		if externalRefs.URL != "" {
			links = append(links, externalRefs.URL)
		}
	}

	// duplicate the vulnerabilities based on the set of unique packages the vulnerability is for
	var allVulns []grypeDB.Vulnerability
	for _, p := range uniquePkgs.All() {
		var qualifiers []qualifier.Qualifier
		matches := uniquePkgs.Matches(p)
		cpes := strset.New()
		for _, m := range matches {
			cpes.Add(grypeNamespace.Resolver().Normalize(m.Criteria))
		}

		if p.PlatformCPE != "" {
			qualifiers = []qualifier.Qualifier{platformcpe.Qualifier{
				Kind: "platform-cpe",
				CPE:  p.PlatformCPE,
			}}
		}

		orderedCPEs := cpes.List()
		sort.Strings(orderedCPEs)

		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                vulnerability.ID,
			PackageQualifiers: qualifiers,
			VersionConstraint: buildConstraints(matches),
			VersionFormat:     strings.ToLower(getVersionFormat(p.Product, orderedCPEs).String()),
			PackageName:       grypeNamespace.Resolver().Normalize(p.Product),
			Namespace:         entryNamespace,
			CPEs:              orderedCPEs,
			Fix:               getFix(matches, cfg.InferNVDFixVersions),
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	allCVSS := vulnerability.CVSS()
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.ID,
		DataSource:   "https://nvd.nist.gov/vuln/detail/" + vulnerability.ID,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     nvd.CvssSummaries(allCVSS).Sorted().Severity(),
		URLs:         links,
		Description:  vulnerability.Description(),
		Cvss:         getCvss(allCVSS...),
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getVersionFormat(name string, cpes []string) version.Format {
	if pkg.HasJvmPackageName(name) {
		return version.JVMFormat
	}
	for _, c := range cpes {
		att, err := cpe.NewAttributes(c)
		if err != nil {
			continue
		}
		if pkg.HasJvmPackageName(att.Product) {
			return version.JVMFormat
		}
	}
	return version.UnknownFormat
}

func getFix(matches []nvd.CpeMatch, inferNVDFixVersions bool) grypeDB.Fix {
	if !inferNVDFixVersions {
		return grypeDB.Fix{
			State: grypeDB.UnknownFixState,
		}
	}

	possiblyFixed := strset.New()
	knownAffected := strset.New()
	unspecifiedSet := strset.New("*", "-", "*")

	for _, match := range matches {
		if !match.Vulnerable {
			continue
		}

		if match.VersionEndExcluding != nil && !unspecifiedSet.Has(*match.VersionEndExcluding) {
			possiblyFixed.Add(*match.VersionEndExcluding)
		}

		if match.VersionStartIncluding != nil && !unspecifiedSet.Has(*match.VersionStartIncluding) {
			knownAffected.Add(*match.VersionStartIncluding)
		}

		if match.VersionEndIncluding != nil && !unspecifiedSet.Has(*match.VersionEndIncluding) {
			knownAffected.Add(*match.VersionEndIncluding)
		}

		matchCPE, err := cpe.New(match.Criteria, cpe.DeclaredSource)
		if err != nil {
			continue
		}

		if !unspecifiedSet.Has(matchCPE.Attributes.Version) {
			knownAffected.Add(matchCPE.Attributes.Version)
		}
	}

	possiblyFixed.Remove(knownAffected.List()...)

	var fixes []string
	fixState := grypeDB.UnknownFixState
	if possiblyFixed.Size() > 0 {
		fixState = grypeDB.FixedState
		fixes = possiblyFixed.List()
		slices.Sort(fixes)
	}

	return grypeDB.Fix{
		Versions: fixes,
		State:    fixState,
	}
}

func getCvss(cvss ...nvd.CvssSummary) []grypeDB.Cvss {
	var results []grypeDB.Cvss
	for _, c := range cvss {
		results = append(results, grypeDB.Cvss{
			Source:  c.Source,
			Type:    string(c.Type),
			Version: c.Version,
			Vector:  c.Vector,
			Metrics: grypeDB.CvssMetrics{
				BaseScore:           c.BaseScore,
				ExploitabilityScore: c.ExploitabilityScore,
				ImpactScore:         c.ImpactScore,
			},
		})
	}
	return results
}
