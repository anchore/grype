package nvd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
	"github.com/anchore/syft/syft/cpe"
)

type affectedRangeSet map[affectedCPERange]struct{}

type affectedCPERange struct {
	ExactVersion          string
	ExactUpdate           string
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
	FixInfo               *nvd.FixInfo
}

func newAffectedRanges(rs ...affectedCPERange) affectedRangeSet {
	s := make(affectedRangeSet)
	s.addRanges(rs...)
	return s
}

func newAffectedRange(match nvd.CpeMatch) affectedCPERange {
	return affectedCPERange{
		VersionStartIncluding: nonEmptyValue(match.VersionStartIncluding),
		VersionStartExcluding: nonEmptyValue(match.VersionStartExcluding),
		VersionEndIncluding:   nonEmptyValue(match.VersionEndIncluding),
		VersionEndExcluding:   nonEmptyValue(match.VersionEndExcluding),
		FixInfo:               match.Fix,
	}
}

func (s affectedRangeSet) addRanges(rs ...affectedCPERange) {
	for _, r := range rs {
		s[r] = struct{}{}
	}
}

func (s affectedRangeSet) toSlice() []affectedCPERange {
	var result []affectedCPERange
	for r := range s {
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ExactVersion != result[j].ExactVersion {
			return result[i].ExactVersion < result[j].ExactVersion
		}
		if result[i].ExactUpdate != result[j].ExactUpdate {
			return result[i].ExactUpdate < result[j].ExactUpdate
		}
		if result[i].VersionStartIncluding != result[j].VersionStartIncluding {
			return result[i].VersionStartIncluding < result[j].VersionStartIncluding
		}
		if result[i].VersionStartExcluding != result[j].VersionStartExcluding {
			return result[i].VersionStartExcluding < result[j].VersionStartExcluding
		}
		if result[i].VersionEndIncluding != result[j].VersionEndIncluding {
			return result[i].VersionEndIncluding < result[j].VersionEndIncluding
		}
		if result[i].VersionEndExcluding != result[j].VersionEndExcluding {
			return result[i].VersionEndExcluding < result[j].VersionEndExcluding
		}
		return false
	})
	return result
}

func (r affectedCPERange) String() string {
	constraints := make([]string, 0)
	if r.VersionStartIncluding != "" {
		constraints = append(constraints, fmt.Sprintf(">= %s", r.VersionStartIncluding))
	} else if r.VersionStartExcluding != "" {
		constraints = append(constraints, fmt.Sprintf("> %s", r.VersionStartExcluding))
	}

	if r.VersionEndExcluding != "" {
		constraints = append(constraints, fmt.Sprintf("< %s", r.VersionEndExcluding))
	} else if r.VersionEndIncluding != "" {
		constraints = append(constraints, fmt.Sprintf("<= %s", r.VersionEndIncluding))
	}

	if len(constraints) == 0 {
		version := r.ExactVersion
		update := r.ExactUpdate
		if version != cpe.Any && version != "-" {
			if update != cpe.Any && update != "-" {
				version = fmt.Sprintf("%s-%s", version, update)
			}

			constraints = append(constraints, fmt.Sprintf("= %s", version))
		}
	}

	return strings.Join(constraints, ", ")
}

func nonEmptyValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
