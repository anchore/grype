package internal

import (
	"fmt"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// onlyVulnerableTargets returns a criteria object that tests vulnerability qualifiers against the package vulnerability rules.
// TODO: in the future this should be moved to underneath the store to avoid the need to recompute CPE comparisons and to leverage ecosystem aliases for target software
func onlyVulnerableTargets(p pkg.Package) vulnerability.Criteria {
	return search.ByFunc(func(v vulnerability.Vulnerability) (bool, string, error) {
		matches, reasons := isVulnerableTarget(p, v)
		return matches, reasons, nil
	})
}

// Determines if a vulnerability is an accurate match using the vulnerability's cpes' target software
func isVulnerableTarget(p pkg.Package, vuln vulnerability.Vulnerability) (bool, string) {
	// Exclude OS package types from this logic, since they could be embedding any type of ecosystem package
	if isOSPackage(p) {
		return true, ""
	}

	packageTargetSwSet, vulnTargetSwSet := matchTargetSoftware(p.CPEs, vuln.CPEs)
	if len(vuln.CPEs) > 0 && packageTargetSwSet.IsEmpty() {
		reason := fmt.Sprintf("vulnerability target software(s) (%q) do not align with %s", strings.Join(vulnTargetSwSet.List(), ", "), packageElements(p, packageTargetSwSet.List()))
		return false, reason
	}

	// only strictly use CPE attributes to filter binary and unknown package types
	if p.Type == syftPkg.BinaryPkg || p.Type == syftPkg.UnknownPkg || p.Type == "" {
		if hasIntersectingTargetSoftware(packageTargetSwSet, vulnTargetSwSet) {
			// we have at least one target software in common
			return true, ""
		}

		// the package has a * target software, so should match with anything that's on the CPE.
		// note that this is two way (either the package has a * or the vuln has a * target software).
		if packageTargetSwSet.Has(wfn.Any) || vulnTargetSwSet.Has(wfn.Any) {
			return true, ""
		}

		reason := fmt.Sprintf("vulnerability target software(s) (%q) do not align with %s", strings.Join(vulnTargetSwSet.List(), ", "), packageElements(p, packageTargetSwSet.List()))
		return false, reason
	}

	// There are quite a few cases within java where other ecosystem components (particularly javascript packages)
	// are embedded directly within jar files, so we can't yet make this assumption with java as it will cause dropping
	// of valid vulnerabilities that syft has specific logic https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/common/cpe/candidate_by_package_type.go#L48-L75
	// to ensure will be surfaced
	if p.Language == syftPkg.Java {
		return true, ""
	}

	// if there are no CPEs then we can't make a decision
	if len(vuln.CPEs) == 0 {
		return true, ""
	}

	if hasIntersectingTargetSoftware(packageTargetSwSet, vulnTargetSwSet) {
		// we have at least one target software in common
		return true, ""
	}

	return refuteTargetSoftwareByPackageAttributes(p, vuln, packageTargetSwSet)
}

func refuteTargetSoftwareByPackageAttributes(p pkg.Package, vuln vulnerability.Vulnerability, packageTargetSwSet *strset.Set) (bool, string) {
	// this is purely based on package attributes and does not consider any package CPE target softwares (which the store already considers)
	var mismatchedTargetSoftware []string
	for _, c := range vuln.CPEs {
		targetSW := c.Attributes.TargetSW
		mismatchWithUnknownLanguage := syftPkg.LanguageByName(targetSW) != p.Language && isUnknownTarget(targetSW)
		unspecifiedTargetSW := targetSW == wfn.Any || targetSW == wfn.NA
		matchesByLanguage := syftPkg.LanguageByName(targetSW) == p.Language
		matchesByPackageType := internal.CPETargetSoftwareToPackageType(targetSW) == p.Type
		if unspecifiedTargetSW || matchesByLanguage || matchesByPackageType || mismatchWithUnknownLanguage {
			return true, ""
		}
		mismatchedTargetSoftware = append(mismatchedTargetSoftware, targetSW)
	}

	reason := fmt.Sprintf("vulnerability target software(s) (%q) do not align with %s", strings.Join(mismatchedTargetSoftware, ", "), packageElements(p, packageTargetSwSet.List()))
	return false, reason
}

func isOSPackage(p pkg.Package) bool {
	return p.Type == syftPkg.AlpmPkg || p.Type == syftPkg.ApkPkg || p.Type == syftPkg.DebPkg || p.Type == syftPkg.KbPkg || p.Type == syftPkg.PortagePkg || p.Type == syftPkg.RpmPkg
}

func isUnknownTarget(targetSW string) bool {
	if syftPkg.LanguageByName(targetSW) != syftPkg.UnknownLanguage {
		return false
	}

	// There are some common target software CPE components which are not currently
	// supported by syft but are signifcant sources of false positives and should be
	// considered known for the purposes of filtering here
	known := map[string]bool{
		"joomla":    true,
		"joomla\\!": true,
		"drupal":    true,
	}

	if _, ok := known[targetSW]; ok {
		return false
	}

	return true
}

func matchTargetSoftware(pkgCPEs []cpe.CPE, vulnCPEs []cpe.CPE) (*strset.Set, *strset.Set) {
	pkgTsw := strset.New()
	vulnTsw := strset.New()
	for _, c := range vulnCPEs {
		for _, p := range pkgCPEs {
			if matchesAttributesExceptVersionAndTSW(c.Attributes, p.Attributes) {
				// include any value including empty string (which means ANY value)
				pkgTsw.Add(p.Attributes.TargetSW)
				vulnTsw.Add(c.Attributes.TargetSW)
			}
		}
	}
	return pkgTsw, vulnTsw
}

func matchesAttributesExceptVersionAndTSW(a1 cpe.Attributes, a2 cpe.Attributes) bool {
	// skip version, update, and target software
	if !matchesAttribute(a1.Product, a2.Product) ||
		!matchesAttribute(a1.Vendor, a2.Vendor) ||
		!matchesAttribute(a1.Part, a2.Part) ||
		!matchesAttribute(a1.Language, a2.Language) ||
		!matchesAttribute(a1.SWEdition, a2.SWEdition) ||
		!matchesAttribute(a1.TargetHW, a2.TargetHW) ||
		!matchesAttribute(a1.Other, a2.Other) ||
		!matchesAttribute(a1.Edition, a2.Edition) {
		return false
	}
	return true
}

func matchesAttribute(a1, a2 string) bool {
	return a1 == "" || a2 == "" || strings.EqualFold(a1, a2)
}

func hasIntersectingTargetSoftware(set1, set2 *strset.Set) bool {
	set1Pkg := pkgTypesFromTargetSoftware(set1.List())
	set2Pkg := pkgTypesFromTargetSoftware(set2.List())
	intersection := strset.Intersection(set1Pkg, set2Pkg)
	return !intersection.IsEmpty()
}

func pkgTypesFromTargetSoftware(ts []string) *strset.Set {
	pkgTypes := strset.New()
	for _, ts := range ts {
		pt := internal.CPETargetSoftwareToPackageType(ts)
		if pt != "" {
			pkgTypes.Add(string(pt))
		}
	}
	return pkgTypes
}

func packageElements(p pkg.Package, ts []string) string {
	nameVersion := fmt.Sprintf("%s@%s", p.Name, p.Version)

	pType := string(p.Type)
	if pType == "" {
		pType = "?"
	}

	pLanguage := string(p.Language)
	if pLanguage == "" {
		pLanguage = "?"
	}

	targetSW := strings.Join(ts, ",")
	if (len(ts) == 0) || (len(ts) == 1 && ts[0] == wfn.Any) {
		targetSW = "*"
	}

	return fmt.Sprintf("pkg(%s type=%q language=%q targets=%q)", nameVersion, pType, pLanguage, targetSW)
}
