package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var _ Comparator = (*gemVersion)(nil)

type segmentKind int

const (
	numSeg segmentKind = iota
	strSeg
)

type segment struct {
	kind segmentKind
	num  int
	str  string
}
type gemVersion struct {
	original     string
	segments     []segment
	canonical    []segment
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

func newGemVersion(raw string) (gemVersion, error) {
	original := raw

	processed := strings.TrimSpace(cleanArchFromVersion(raw))
	if processed == "" {
		processed = "0"
	}

	if !correctnessRegexp.MatchString(processed) {
		return gemVersion{}, fmt.Errorf("malformed version number string %q", original)
	}

	processed = strings.ReplaceAll(processed, "-", ".pre.")

	isPrerelease := strings.Contains(processed, ".pre.")

	segments, err := partitionSegments(processed)
	if err != nil {
		return gemVersion{}, err
	}

	if len(segments) == 0 {
		segments = []segment{{kind: numSeg, num: 0}}
	}

	canonical := normalizeSegments(segments, isPrerelease)

	return gemVersion{
		original:     original,
		segments:     segments,
		canonical:    canonical,
		isPrerelease: isPrerelease,
	}, nil
}

func normalizeSegments(in []segment, prerelease bool) []segment {
	out := make([]segment, len(in))
	copy(out, in)

	// trim trailing numeric zeros
	last := len(out) - 1
	for last >= 0 {
		if out[last].kind != numSeg || out[last].num != 0 {
			break
		}
		last--
	}
	out = out[:last+1]

	if len(out) == 0 {
		return []segment{{kind: numSeg, num: 0}}
	}

	// prune intermediate zeros before prerelease
	if !prerelease {
		return out
	}

	firstStr := -1
	for i := range out {
		if out[i].kind == strSeg {
			firstStr = i
			break
		}
	}

	if firstStr == -1 {
		return out
	}

	return out
}

func (v gemVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newGemVersion(other.Raw)
	if err != nil {
		return 0, invalidFormatError(GemFormat, other.Raw, err)
	}

	return v.compare(o)
}

func (v gemVersion) compare(other gemVersion) (int, error) {
	result := compareSegments(v.canonical, other.canonical)
	return result, nil
}

func (v *gemVersion) String() string {
	return v.original
}

func partitionSegments(versionString string) ([]segment, error) {
	parts := segmentRegexp.FindAllString(versionString, -1)

	out := make([]segment, 0, len(parts))

	for _, s := range parts {
		if num, err := strconv.Atoi(s); err == nil {
			out = append(out, segment{kind: numSeg, num: num})
		} else {
			out = append(out, segment{kind: strSeg, str: s})
		}
	}

	return out, nil
}

func compareSegments(left, right []segment) int {
	n := min(len(left), len(right))

	for i := 0; i < n; i++ {
		l, r := left[i], right[i]

		switch {
		case l.kind == numSeg && r.kind == numSeg:
			if l.num != r.num {
				if l.num < r.num {
					return -1
				}
				return 1
			}

		case l.kind == strSeg && r.kind == strSeg:
			if l.str != r.str {
				if l.str < r.str {
					return -1
				}
				return 1
			}

		case l.kind == numSeg && r.kind == strSeg:
			return 1

		case l.kind == strSeg && r.kind == numSeg:
			return -1
		}
	}

	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func cleanArchFromVersion(raw string) string {
	archSuffixRegex := regexp.MustCompile(`-(x86|universal|arm64|aarch64|x64|powerpc|sparc|mswin|java|dalvik|arm)$`)
	return archSuffixRegex.ReplaceAllString(raw, "")
}
