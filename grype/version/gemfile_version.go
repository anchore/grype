package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var _ Comparator = (*rubyVersion)(nil)

type rubyVersion struct {
	original     string
	segments     []any
	canonical    []any
	isPrerelease bool
}

const (
	rubySegmentPattern     = `(\d+|[a-zA-Z]+)`
	rubyCorrectnessPattern = `^[0-9a-zA-Z.\-]+$`
)

var (
	segmentRegexp     = regexp.MustCompile(rubySegmentPattern)
	correctnessRegexp = regexp.MustCompile(rubyCorrectnessPattern)
)

func trimTrailingZeros(segments []any) []any {
	if len(segments) <= 1 {
		if len(segments) == 1 {
			if num, ok := segments[0].(int); ok && num == 0 {
				return []any{0}
			}
		}
		return segments
	}

	lastSignificantIdx := -1
	for i := len(segments) - 1; i >= 0; i-- {
		num, ok := segments[i].(int)
		if !ok || num != 0 {
			lastSignificantIdx = i
			break
		}
		// It's a numeric zero, continue looking
	}

	if lastSignificantIdx == -1 {
		return []any{0}
	}
	return segments[:lastSignificantIdx+1]
}

func trimIntermediateZeros(segments []any, isPrerelease bool) []any {
	if !isPrerelease || len(segments) == 0 {
		return segments
	}

	firstLetterIdx := -1
	for i, seg := range segments {
		if _, ok := seg.(string); ok {
			firstLetterIdx = i
			break
		}
	}

	if firstLetterIdx == -1 {
		return segments
	}

	segmentsBeforeLetter := []any{}
	if firstLetterIdx > 0 {
		segmentsBeforeLetter = segments[:firstLetterIdx]
	}

	trimmedPrefix := []any{}
	if len(segmentsBeforeLetter) > 0 {
		lastNonZeroInPrefixIdx := -1
		for i := len(segmentsBeforeLetter) - 1; i >= 0; i-- {
			num, ok := segmentsBeforeLetter[i].(int)
			if !ok || num != 0 {
				lastNonZeroInPrefixIdx = i
				break
			}
		}
		if lastNonZeroInPrefixIdx != -1 {
			trimmedPrefix = segmentsBeforeLetter[:lastNonZeroInPrefixIdx+1]
		}
	}

	reconstructed := make([]any, 0, len(trimmedPrefix)+len(segments)-firstLetterIdx)
	reconstructed = append(reconstructed, trimmedPrefix...)
	reconstructed = append(reconstructed, segments[firstLetterIdx:]...)

	return reconstructed
}

func newGemVersion(raw string) (*rubyVersion, error) {
	original := raw
	processed := cleanArchFromVersion(raw)
	if processed == "" || strings.TrimSpace(processed) == "" {
		processed = "0"
	} else {
		processed = strings.TrimSpace(processed)
	}

	if !correctnessRegexp.MatchString(processed) {
		return nil, fmt.Errorf("malformed version number string %q", original)
	}
	processed = strings.ReplaceAll(processed, "-", ".pre.")

	isPrerelease := strings.ContainsAny(processed, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	segments, err := partitionSegments(processed)
	if err != nil {
		return nil, fmt.Errorf("malformed version number string %q: %w", original, err)
	}
	if len(segments) == 0 {
		if processed == "0" {
			segments = []any{0}
		} else {
			return nil, fmt.Errorf("malformed version number string %q (no valid segments after processing)", original)
		}
	}
	canonical := make([]any, len(segments))
	copy(canonical, segments)

	canonical = trimTrailingZeros(canonical)
	canonical = trimIntermediateZeros(canonical, isPrerelease)

	if len(canonical) == 0 {
		canonical = []any{0}
	}

	return &rubyVersion{
		original:     original,
		segments:     segments,
		canonical:    canonical,
		isPrerelease: isPrerelease,
	}, nil
}

func partitionSegments(versionString string) ([]any, error) {
	if versionString == "" {
		return []any{}, fmt.Errorf("cannot partition empty version string")
	}
	if strings.Contains(versionString, "..") {
		return nil, fmt.Errorf("invalid version string (double dot): %q", versionString)
	}
	if (strings.HasPrefix(versionString, ".") && versionString != ".") ||
		(strings.HasSuffix(versionString, ".") && versionString != ".") {
		if len(versionString) > 1 {
			return nil, fmt.Errorf("invalid version string (leading/trailing dot): %q", versionString)
		}
	}

	parts := segmentRegexp.FindAllString(versionString, -1)
	if len(parts) == 0 {
		if versionString == "0" {
			return []any{0}, nil
		}
		return nil, fmt.Errorf("no valid segments found in %q", versionString)
	}

	segments := make([]any, 0, len(parts))
	for _, s := range parts {
		if n, err := strconv.Atoi(s); err == nil {
			segments = append(segments, n)
		} else {
			segments = append(segments, s)
		}
	}
	return segments, nil
}

func compareSegments(left, right []any) (result int, allEqual bool, err error) {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}

	for i := 0; i < limit; i++ {
		l := left[i]
		r := right[i]

		lNum, lIsNum := l.(int)
		lStr, lIsStr := l.(string)
		rNum, rIsNum := r.(int)
		rStr, rIsStr := r.(string)

		if lIsNum && rIsNum {
			if lNum != rNum {
				if lNum < rNum {
					return -1, false, nil
				}
				return 1, false, nil
			}
			continue
		}

		if lIsStr && rIsStr {
			if cmp := strings.Compare(lStr, rStr); cmp != 0 {
				return cmp, false, nil
			}
			continue
		}

		if lIsNum && rIsStr {
			return 1, false, nil
		}
		if lIsStr && rIsNum {
			return -1, false, nil
		}

		return 0, false, fmt.Errorf("internal comparison error: unexpected types %T vs %T", l, r)
	}
	return 0, true, nil
}

func compareLengths(left, right []any, commonResult int) int {
	if commonResult != 0 {
		return commonResult
	}

	lLen := len(left)
	rLen := len(right)

	if lLen == rLen {
		return 0
	}

	if lLen > rLen {
		for i := rLen; i < lLen; i++ {
			seg := left[i]
			if _, isStr := seg.(string); isStr {
				return -1
			}
			if num, isNum := seg.(int); isNum && num != 0 {
				return 1
			}
		}
		return 0
	}

	for i := lLen; i < rLen; i++ {
		seg := right[i]
		if _, isStr := seg.(string); isStr {
			return 1
		}
		if num, isNum := seg.(int); isNum && num != 0 {
			return -1
		}
	}
	return 0
}

func (v *rubyVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, fmt.Errorf("cannot compare with nil version")
	}
	if other.Format != GemFormat && other.Format != UnknownFormat {
		return -1, fmt.Errorf("cannot compare Gem version %q with format %s", v.original, other.Format)
	}

	var otherRubyVer *rubyVersion
	switch {
	case other.rich.rubyVer != nil:
		otherRubyVer = other.rich.rubyVer
	case other.Format == UnknownFormat || other.Format == GemFormat:
		var err error
		otherRubyVer, err = newGemVersion(other.Raw)
		if err != nil {
			return -1, fmt.Errorf("cannot compare Gem version %q with unparsable version %q: %w", v.original, other.Raw, err)
		}
	default:
		return -1, fmt.Errorf("internal error: other version (%s) is GemFormat but has no parsed data and could not be reparsed", other.Raw)
	}

	standardResult, commonSegmentsAreEqual, err := compareSegments(v.canonical, otherRubyVer.canonical)
	if err != nil {
		return -1, err
	}

	if commonSegmentsAreEqual {
		standardResult = compareLengths(v.canonical, otherRubyVer.canonical, standardResult)
	}

	if standardResult == 0 {
		return 0, nil
	}
	return -standardResult, nil
}

func (v *rubyVersion) String() string {
	return v.original
}

func cleanArchFromVersion(raw string) string {
	platforms := []string{"x86", "universal", "arm", "java", "dalvik", "x64", "powerpc", "sparc", "mswin"}
	dash := "-"
	for _, p := range platforms {
		vals := strings.SplitN(raw, dash+p, 2)
		if len(vals) == 2 {
			return vals[0]
		}
	}

	return raw
}
