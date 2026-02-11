package nvd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

type affectedPackageCandidate struct {
	VulnerableCPE cpe.Attributes
	PlatformCPEs  []cpe.Attributes
	Ranges        affectedRangeSet
}

func allCandidates(cve string, configs []nvd.Configuration, cfg Config) ([]affectedPackageCandidate, error) {
	var candidates []affectedPackageCandidate

	for _, config := range configs {
		cs, err := processConfiguration(cve, config, cfg)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, cs...)
	}

	return deduplicateCandidates(candidates), nil
}

// processConfiguration processes a configuration recursively
func processConfiguration(cve string, config nvd.Configuration, cfg Config) ([]affectedPackageCandidate, error) {
	var opPtr = config.Operator
	var op nvd.Operator
	if opPtr != nil {
		op = *opPtr
	} else {
		op = nvd.Or
	}

	if op == nvd.And {
		return processANDNodes(cve, config.Nodes, cfg, 0)
	}
	return processORNodes(cve, config.Nodes, cfg, 0)
}

// processANDNodes handles AND configurations
func processANDNodes(cve string, nodes []nvd.Node, cfg Config, depth int) ([]affectedPackageCandidate, error) {
	depth++
	if depth > 2 {
		log.WithFields("depth", depth, "cve", cve, "operator", "and").Warn("unexpected NVD node configuration depth")
	}
	var candidates []affectedPackageCandidate

	// find all vulnerable CPEs and all platform CPEs across all nodes
	var allVulnerableCPEs []affectedPackageCandidate
	var allPlatformCPEs []cpe.Attributes

	for _, node := range nodes {
		switch node.Operator {
		case nvd.Or:
			vulnCPEs, err := extractVulnerableCPEs(node, cfg)
			if err != nil {
				return nil, err
			}
			allVulnerableCPEs = append(allVulnerableCPEs, vulnCPEs...)
			platformCPEs, err := extractPlatformCPEs(node)
			if err != nil {
				return nil, err
			}
			allPlatformCPEs = append(allPlatformCPEs, platformCPEs...)
		case nvd.And:
			// TODO: when we're processing AND'd nodes at this depth this tends to mean that all the given CPEs must
			// be present in the environment for the vulnerability to be applicable. This isn't something we can
			// express as a single affected package in grype today. We should consider how to handle this case in
			// the future.
			var names []string
			for _, match := range node.CpeMatch {
				short := strings.ReplaceAll(strings.ReplaceAll(match.Criteria, ":*", ""), ":-", "")
				postfix := ""
				if !match.Vulnerable {
					postfix = " (not vulnerable)"
				}
				names = append(names, fmt.Sprintf("%q%s", short, postfix))
			}
			log.WithFields("cve", cve, "criteria", strings.Join(names, " AND ")).Warnf("unsupported NVD node configuration (dropping criteria)")
		}
	}

	// deduplicate CPEs
	uniqueVulnCPEs := make(map[string]affectedPackageCandidate)
	for _, c := range allVulnerableCPEs {
		cKey := cpeKey(c.VulnerableCPE)
		if _, exists := uniqueVulnCPEs[cKey]; !exists {
			uniqueVulnCPEs[cKey] = c
		} else {
			uniqueVulnCPEs[cKey].Ranges.addRanges(c.Ranges.toSlice()...)
		}
	}

	// combine all unique vulnerable CPEs with their associated ranges
	for _, vulnCPE := range uniqueVulnCPEs {
		if len(allPlatformCPEs) == 0 {
			// no platform constraints, app is vulnerable on all platforms
			candidates = append(candidates, vulnCPE)
		} else {
			// associate this vulnerable CPE with all platform CPEs
			vulnCPE.PlatformCPEs = allPlatformCPEs
			candidates = append(candidates, vulnCPE)
		}
	}

	return candidates, nil
}

// processORNodes handles OR configurations
func processORNodes(cve string, nodes []nvd.Node, cfg Config, depth int) ([]affectedPackageCandidate, error) {
	depth++
	if depth > 2 {
		log.WithFields("depth", depth, "cve", cve, "operator", "or").Warnf("unexpected NVD node configuration depth")
	}
	var candidates []affectedPackageCandidate

	for _, node := range nodes {
		switch node.Operator {
		case nvd.And:
			andCandidates, err := processANDNodes(cve, []nvd.Node{node}, cfg, depth)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, andCandidates...)
		case nvd.Or:
			vulnCPEs, err := extractVulnerableCPEs(node, cfg)
			if err != nil {
				return nil, err
			}

			candidates = append(candidates, vulnCPEs...)
		}
	}

	return candidates, nil
}

func deduplicateCandidates(candidates []affectedPackageCandidate) []affectedPackageCandidate {
	candidateMap := make(map[string]*affectedPackageCandidate)

	for _, candidate := range candidates {
		key := cpeKey(candidate.VulnerableCPE)

		existing, exists := candidateMap[key]
		if !exists {
			newCandidate := candidate
			candidateMap[key] = &newCandidate
			continue
		}

		// merge platform CPEs...
		platformMap := make(map[string]struct{})
		for _, platform := range existing.PlatformCPEs {
			platformKey := cpeKey(platform)
			platformMap[platformKey] = struct{}{}
		}

		for _, platform := range candidate.PlatformCPEs {
			platformKey := cpeKey(platform)
			if _, ok := platformMap[platformKey]; !ok {
				existing.PlatformCPEs = append(existing.PlatformCPEs, platform)
				platformMap[platformKey] = struct{}{}
			}
		}

		// merge ranges...
		existing.Ranges.addRanges(candidate.Ranges.toSlice()...)
	}

	var result []affectedPackageCandidate
	for _, candidate := range candidateMap {
		if len(candidate.Ranges) == 0 {
			candidate.Ranges.addRanges(deriveRangesFromCPE(candidate.VulnerableCPE)...)
		}
		result = append(result, *candidate)
	}

	// sort the slice for deterministic output
	sort.Slice(result, func(i, j int) bool {
		return result[i].VulnerableCPE.String() < result[j].VulnerableCPE.String()
	})

	return result
}

func deriveRangesFromCPE(attr cpe.Attributes) []affectedCPERange {
	if attr.Version == cpe.Any {
		return nil
	}

	var update string
	if attr.Update != "-" {
		update = attr.Update
	}

	return []affectedCPERange{
		{
			ExactVersion: attr.Version,
			ExactUpdate:  update,
		},
	}
}

// extractVulnerableCPEs extracts CPES that are both within the CPE part configuration and are explicitly marked as vulnerable
func extractVulnerableCPEs(node nvd.Node, cfg Config) ([]affectedPackageCandidate, error) {
	var candidates []affectedPackageCandidate

	for _, match := range node.CpeMatch {
		if !match.Vulnerable {
			continue
		}

		cpeAttr, err := cpe.NewAttributes(match.Criteria)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CPE '%s': %w", match.Criteria, err)
		}

		// check if this CPE part is in our configured set of parts to process, if not then it should not be considered
		// as an affected package at all
		if !cfg.CPEParts.Has(cpeAttr.Part) {
			continue
		}

		candidate := affectedPackageCandidate{
			VulnerableCPE: cpeAttr,
		}

		if match.VersionStartIncluding != nil || match.VersionStartExcluding != nil ||
			match.VersionEndIncluding != nil || match.VersionEndExcluding != nil {
			candidate.Ranges = newAffectedRanges(newAffectedRange(match))
		} else {
			// no explicit version ranges in the match, check the CPE attributes for an exact version
			candidate.Ranges = newAffectedRanges(deriveRangesFromCPE(cpeAttr)...)
		}

		candidates = append(candidates, candidate)
	}

	return candidates, nil
}

// extractPlatformCPEs extracts all platform CPEs from a node (explicitly non-vulnerable CPEs). Why not just
// use the part indication (i.e. 'h' & 'o' are platform and 'a' is the vulnerable candidate)? Because you can
// find cases where an application is the platform (e.g. kubernetes or openshift).
func extractPlatformCPEs(node nvd.Node) ([]cpe.Attributes, error) {
	var platformCPEs []cpe.Attributes

	for _, match := range node.CpeMatch {
		cpeAttr, err := cpe.NewAttributes(match.Criteria)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CPE '%s': %w", match.Criteria, err)
		}

		if !match.Vulnerable {
			platformCPEs = append(platformCPEs, cpeAttr)
		}
	}

	return platformCPEs, nil
}

// cpeKey generates a unique key for a CPE (everything except for the version and update)
func cpeKey(cpe cpe.Attributes) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s", cpe.Part, cpe.Vendor, cpe.Product, cpe.Edition, cpe.SWEdition, cpe.TargetSW, cpe.TargetHW, cpe.Other, cpe.Language)
}
