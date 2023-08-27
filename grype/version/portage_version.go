package version

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

type portageVersion struct {
	version string
}

func newPortageVersion(raw string) portageVersion {
	return portageVersion{
		version: raw,
	}
}

func (v *portageVersion) Compare(other *Version) (int, error) {
	if other.Format != PortageFormat {
		return -1, fmt.Errorf("unable to compare portage to given format: %s", other.Format)
	}
	if other.rich.portVer == nil {
		return -1, fmt.Errorf("given empty portageVersion object")
	}

	return other.rich.portVer.compare(*v), nil
}

// Compare returns 0 if v == v2, -1 if v < v2, and +1 if v > v2.
func (v portageVersion) compare(v2 portageVersion) int {
	if v.version == v2.version {
		return 0
	}
	return comparePortageVersions(v.version, v2.version)
}

// For the original python implementation, see:
// https://github.com/gentoo/portage/blob/master/lib/portage/versions.py
var (
	versionRegexp = regexp.MustCompile(`(\d+)((\.\d+)*)([a-z]?)((_(pre|p|beta|alpha|rc)\d*)*)(-r(\d+))?`)
	suffixRegexp  = regexp.MustCompile(`^(alpha|beta|rc|pre|p)(\d*)$`)
	suffixValue   = map[string]int{"pre": -2, "p": 0, "alpha": -4, "beta": -3, "rc": -1}
)

//nolint:funlen,gocognit
func comparePortageVersions(a, b string) int {
	match1 := versionRegexp.FindStringSubmatch(a)
	match2 := versionRegexp.FindStringSubmatch(b)
	list1 := []*big.Int{big.NewInt(0)}
	list2 := []*big.Int{big.NewInt(0)}
	list1[0].SetString(match1[1], 10)
	list2[0].SetString(match2[1], 10)
	vlist1 := strings.Split(match1[2], ".")[1:]
	vlist2 := strings.Split(match2[2], ".")[1:]
	vlistMaxLen := len(vlist1)
	if len(vlist2) > vlistMaxLen {
		vlistMaxLen = len(vlist2)
	}

	for index := 0; index < vlistMaxLen; index++ {
		switch {
		case len(vlist1) <= index:
			list1 = append(list1, big.NewInt(-1))
			i := big.NewInt(0)
			i.SetString(vlist2[index], 10)
			list2 = append(list2, i)
		case len(vlist2) <= index:
			list2 = append(list2, big.NewInt(-1))
			i := big.NewInt(0)
			i.SetString(vlist1[index], 10)
			list1 = append(list1, i)
		case !strings.HasPrefix(vlist1[index], "0") && !strings.HasPrefix(vlist2[index], "0"):
			i := big.NewInt(0)
			i.SetString(vlist1[index], 10)
			list1 = append(list1, i)
			j := big.NewInt(0)
			j.SetString(vlist2[index], 10)
			list2 = append(list2, j)
		default:
			maxLen := len(vlist1[index])
			if len(vlist2[index]) > maxLen {
				maxLen = len(vlist2[index])
			}
			if len(vlist1[index]) < maxLen {
				vlist1[index] += strings.Repeat("0", maxLen-len(vlist1[index]))
			}
			if len(vlist2[index]) < maxLen {
				vlist2[index] += strings.Repeat("0", maxLen-len(vlist2[index]))
			}
			i := big.NewInt(0)
			i.SetString(vlist1[index], 10)
			list1 = append(list1, i)
			j := big.NewInt(0)
			j.SetString(vlist2[index], 10)
			list2 = append(list2, j)
		}
	}

	if len(match1[4]) != 0 {
		r := []rune(match1[4])
		i := big.NewInt(int64(r[0]))
		list1 = append(list1, i)
	}

	if len(match2[4]) != 0 {
		r := []rune(match2[4])
		i := big.NewInt(int64(r[0]))
		list2 = append(list2, i)
	}

	maxLen := len(list1)
	if len(list2) > maxLen {
		maxLen = len(list2)
	}
	for index := 0; index < maxLen; index++ {
		if len(list1) <= index {
			return -1
		}
		if len(list2) <= index {
			return 1
		}
		c := list1[index].Cmp(list2[index])
		if c != 0 {
			return c
		}
	}

	slist1 := strings.Split(match1[5], "_")[1:]
	slist2 := strings.Split(match2[5], "_")[1:]
	maxLen = len(slist1)
	if len(slist2) > maxLen {
		maxLen = len(slist2)
	}
	for index := 0; index < maxLen; index++ {
		s1 := []string{"p", "-1"}
		s2 := []string{"p", "-1"}
		if len(slist1) > index {
			s1 = suffixRegexp.FindStringSubmatch(slist1[index])[1:]
			if s1[1] == "" {
				s1[1] = "0"
			}
		}
		if len(slist2) > index {
			s2 = suffixRegexp.FindStringSubmatch(slist2[index])[1:]
			if s2[1] == "" {
				s2[1] = "0"
			}
		}
		if s1[0] != s2[0] {
			v1 := suffixValue[s1[0]]
			v2 := suffixValue[s2[0]]
			if v1 > v2 {
				return 1
			}

			return -1
		}
		if s1[1] != s2[1] {
			i := big.NewInt(0)
			i.SetString(s1[1], 10)
			j := big.NewInt(0)
			j.SetString(s2[1], 10)
			c := i.Cmp(j)
			if c != 0 {
				return c
			}
		}
	}

	r1 := big.NewInt(0)
	if match1[9] != "" {
		r1.SetString(match1[9], 10)
	}
	r2 := big.NewInt(0)
	if match2[9] != "" {
		r2.SetString(match2[9], 10)
	}

	return r1.Cmp(r2)
}
