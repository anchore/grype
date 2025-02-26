package models

import (
	"sort"
	"strings"

	"github.com/anchore/grype/internal/log"
)

type SortStrategy string

const (
	SortBySeverity      SortStrategy = "severity"
	SortByPackage       SortStrategy = "package"
	SortByVulnerability SortStrategy = "vulnerability"
	SortByThreat        SortStrategy = "threat"

	defaultSortStrategy = SortByPackage
)

func SortStrategies() []SortStrategy {
	return []SortStrategy{SortByPackage, SortByVulnerability, SortBySeverity, SortByThreat}
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
		compareByPackageName,
		compareByPackageVersion,
		compareByPackageType,
		compareBySeverity,
		compareByVulnerabilityID,
	},
	SortByVulnerability: {
		compareByVulnerabilityID,
		compareByPackageName,
		compareByPackageVersion,
		compareByPackageType,
		compareBySeverity,
	},
	SortBySeverity: {
		compareBySeverity,
		compareByVulnerabilityID,
		compareByPackageName,
		compareByPackageVersion,
		compareByPackageType,
	},
	SortByThreat: {
		compareByThreatScore,
		compareBySeverity,
		compareByVulnerabilityID,
		compareByPackageName,
		compareByPackageVersion,
		compareByPackageType,
	},
}

// SortMatches sorts matches based on a strategy name
func SortMatches(matches []Match, strategyName SortStrategy) {
	sortWithStrategy(matches, getSortStrategy(strategyName))
}

func getSortStrategy(strategyName SortStrategy) sortStrategyImpl {
	strategy, exists := matchSortStrategy[strategyName]
	if !exists {
		log.WithFields("strategy", strategyName).Debugf("unknown sort strategy, falling back to default of %q", defaultSortStrategy)
		strategy = matchSortStrategy[defaultSortStrategy]
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
	aScore := severityScore(a.Vulnerability.Severity)
	bScore := severityScore(b.Vulnerability.Severity)

	switch {
	case aScore > bScore: // higher severity first
		return -1
	case aScore < bScore:
		return 1
	default:
		return 0
	}
}

func compareByThreatScore(a, b Match) int {
	aScore := a.Vulnerability.ThreatScore
	bScore := b.Vulnerability.ThreatScore

	switch {
	case aScore > bScore: // higher threat first
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

// severityScore maps severity strings to numeric scores for comparison
func severityScore(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	default:
		return 0
	}
}
