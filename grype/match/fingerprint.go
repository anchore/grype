package match

import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/grype/grype/pkg"
)

type Fingerprint struct {
	vulnerabilityID        string
	vulnerabilityNamespace string
	vulnerabilityFixes     string
	packageID              pkg.ID // note: this encodes package name, version, type, location
}

func (m Fingerprint) String() string {
	return fmt.Sprintf("Fingerprint(vuln=%q namespace=%q fixes=%q package=%q)", m.vulnerabilityID, m.vulnerabilityNamespace, m.vulnerabilityFixes, m.packageID)
}

func (m Fingerprint) ID() string {
	f, err := hashstructure.Hash(&m, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%x", f)
}

type FingerprintSet struct {
	order        []Fingerprint
	fingerprints map[Fingerprint]struct{}
}

func NewFingerprintSet(fs ...Fingerprint) FingerprintSet {
	set := FingerprintSet{
		fingerprints: make(map[Fingerprint]struct{}),
	}

	set.Add(fs...)

	return set
}

func (s FingerprintSet) Add(fs ...Fingerprint) {
	for _, f := range fs {
		if _, ok := s.fingerprints[f]; ok {
			continue
		}
		s.order = append(s.order, f)
		s.fingerprints[f] = struct{}{}
	}
}

func (s FingerprintSet) Remove(fs ...Fingerprint) {
	for _, f := range fs {
		if _, ok := s.fingerprints[f]; !ok {
			continue
		}
		for i, f2 := range s.order {
			if f2 == f {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		delete(s.fingerprints, f)
	}
}

func (s FingerprintSet) Contains(f Fingerprint) bool {
	_, ok := s.fingerprints[f]
	return ok
}

func (s FingerprintSet) Len() int {
	return len(s.fingerprints)
}

func (s FingerprintSet) ToSlice() []Fingerprint {
	cpy := make([]Fingerprint, len(s.order))
	copy(cpy, s.order)
	return cpy
}
