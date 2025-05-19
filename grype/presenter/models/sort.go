package models

import (
	"sort"
	"strings"

	"github.com/anchore/grype/internal/log"
)

type SortStrategy string

const (
	SortByPackage       SortStrategy = "package"
	SortBySeverity      SortStrategy = "severity"
	SortByThreat        SortStrategy = "epss"
	SortByRisk          SortStrategy = "risk"
	SortByKEV           SortStrategy = "kev"
	SortByVulnerability SortStrategy = "vulnerability"

	DefaultSortStrategy = SortByRisk
)

func SortStrategies() []SortStrategy {
	return []SortStrategy{SortByPackage, SortBySeverity, SortByThreat, SortByRisk, SortByKEV, SortByVulnerability}
}

func (s SortStrategy) String() string {
	return string(s)
}

// compareFunc defines a comparison function between two Match values
// Returns:
//
//	-1: if a should come before b
//	 0: if a and b are equal for this comparison
//	 1: if a should come after b
type compareFunc func(a, b Match) int

// sortStrategyImpl defines a strategy for sorting with a slice of comparison functions
type sortStrategyImpl []compareFunc

// matchSortStrategy provides predefined sort strategies for Match
var matchSortStrategy = map[SortStrategy]sortStrategyImpl{
	SortByPackage: {
		comparePackageAttributes,
		compareVulnerabilityAttributes,
	},
	SortByVulnerability: {
		compareVulnerabilityAttributes,
		comparePackageAttributes,
	},
	SortBySeverity: {
		// severity and tangential attributes...
		compareBySeverity,
		compareByRisk,
		compareByEPSSPercentile,
		// followed by package attributes...
		comparePackageAttributes,
		// followed by the remaining vulnerability attributes...
		compareByVulnerabilityID,
	},
	SortByThreat: {
		// epss and tangential attributes...
		compareByEPSSPercentile,
		compareByRisk,
		compareBySeverity,
		// followed by package attributes...
		comparePackageAttributes,
		// followed by the remaining vulnerability attributes...
		compareByVulnerabilityID,
	},
	SortByRisk: {
		// risk and tangential attributes...
		compareByRisk,
		compareBySeverity,
		compareByEPSSPercentile,
		// followed by package attributes...
		comparePackageAttributes,
		// followed by the remaining vulnerability attributes...
		compareByVulnerabilityID,
	},
	SortByKEV: {
		compareByKEV,
		// risk and tangential attributes...
		compareByRisk,
		compareBySeverity,
		compareByEPSSPercentile,
		// followed by package attributes...
		comparePackageAttributes,
		// followed by the remaining vulnerability attributes...
		compareByVulnerabilityID,
	},
}

func compareVulnerabilityAttributes(a, b Match) int {
	return combine(
		compareByVulnerabilityID,
		compareByRisk,
		compareBySeverity,
		compareByEPSSPercentile,
	)(a, b)
}

func comparePackageAttributes(a, b Match) int {
	return combine(
		compareByPackageName,
		compareByPackageVersion,
		compareByPackageType,
	)(a, b)
}

func combine(impls ...compareFunc) compareFunc {
	return func(a, b Match) int {
		for _, impl := range impls {
			result := impl(a, b)
			if result != 0 {
				return result
			}
		}
		return 0
	}
}

// SortMatches sorts matches based on a strategy name
func SortMatches(matches []Match, strategyName SortStrategy) {
	sortWithStrategy(matches, getSortStrategy(strategyName))
}

func getSortStrategy(strategyName SortStrategy) sortStrategyImpl {
	strategy, exists := matchSortStrategy[strategyName]
	if !exists {
		log.WithFields("strategy", strategyName).Debugf("unknown sort strategy, falling back to default of %q", DefaultSortStrategy)
		strategy = matchSortStrategy[DefaultSortStrategy]
	}
	return strategy
}

func sortWithStrategy(matches []Match, strategy sortStrategyImpl) {
	sort.Slice(matches, func(i, j int) bool {
		for _, compare := range strategy {
			result := compare(matches[i], matches[j])
			if result != 0 {
				// we are implementing a "less" function, so we want to return true if the result is negative
				return result < 0
			}
		}
		return false // all comparisons are equal
	})
}

func compareByVulnerabilityID(a, b Match) int {
	aID := a.Vulnerability.ID
	bID := b.Vulnerability.ID

	switch {
	case aID < bID:
		return -1
	case aID > bID:
		return 1
	default:
		return 0
	}
}

func compareBySeverity(a, b Match) int {
	aScore := severityPriority(a.Vulnerability.Severity)
	bScore := severityPriority(b.Vulnerability.Severity)

	switch {
	case aScore < bScore: // higher severity first
		return -1
	case aScore > bScore:
		return 1
	default:
		return 0
	}
}

func compareByEPSSPercentile(a, b Match) int {
	aScore := epssPercentile(a.Vulnerability.EPSS)
	bScore := epssPercentile(b.Vulnerability.EPSS)

	switch {
	case aScore > bScore: // higher severity first
		return -1
	case aScore < bScore:
		return 1
	default:
		return 0
	}
}

func compareByPackageName(a, b Match) int {
	aName := a.Artifact.Name
	bName := b.Artifact.Name

	switch {
	case aName < bName:
		return -1
	case aName > bName:
		return 1
	default:
		return 0
	}
}

func compareByPackageVersion(a, b Match) int {
	aVersion := a.Artifact.Version
	bVersion := b.Artifact.Version

	switch {
	case aVersion < bVersion:
		return -1
	case aVersion > bVersion:
		return 1
	default:
		return 0
	}
}

func compareByPackageType(a, b Match) int {
	aType := a.Artifact.Type
	bType := b.Artifact.Type

	switch {
	case aType < bType:
		return -1
	case aType > bType:
		return 1
	default:
		return 0
	}
}

func compareByRisk(a, b Match) int {
	aRisk := a.Vulnerability.Risk
	bRisk := b.Vulnerability.Risk

	switch {
	case aRisk > bRisk:
		return -1
	case aRisk < bRisk:
		return 1
	default:
		return 0
	}
}

func compareByKEV(a, b Match) int {
	aKEV := len(a.Vulnerability.KnownExploited)
	bKEV := len(b.Vulnerability.KnownExploited)

	switch {
	case aKEV > bKEV:
		return -1
	case aKEV < bKEV:
		return 1
	default:
		return 0
	}
}

func epssPercentile(es []EPSS) float64 {
	switch len(es) {
	case 0:
		return 0.0
	case 1:
		return es[0].Percentile
	}
	sort.Slice(es, func(i, j int) bool {
		return es[i].Percentile > es[j].Percentile
	})
	return es[0].Percentile
}

// severityPriority maps severity strings to numeric priority for comparison (the lowest value is most severe)
func severityPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	case "negligible":
		return 5
	default:
		return 100 // least severe
	}
}
