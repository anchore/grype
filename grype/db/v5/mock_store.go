package v5

import (
	"github.com/anchore/grype/grype/vulnerability"
)

type MockStore struct {
	Vulnerabilities []vulnerability.Vulnerability
	Metadata        []vulnerability.Metadata
	Exclusions      []VulnerabilityMatchExclusion
}

// NewMockStore returns a new mock implementation of a Grype database store. If
// the stubFn parameter is not set to nil, the given stub function will be used
// to modify the data in the mock store, such as in preparation for tests.
func NewMockStore(stubFuncs ...func(*MockStore)) *MockStore {
	d := &MockStore{}
	for _, stubFunc := range stubFuncs {
		stubFunc(d)
	}
	return d
}

var _ interface {
	vulnerability.Provider
} = (*MockStore)(nil)

func (s *MockStore) Add(vulns ...vulnerability.Vulnerability) *MockStore {
	s.Vulnerabilities = append(s.Vulnerabilities, vulns...)
	return s
}

// func (s *MockStore) GetID() (*ID, error) {
//	return &ID{
//		BuildTimestamp: time.Now(),
//		SchemaVersion:  SchemaVersion,
//	}, nil
//}

// func (s *MockStore) DiffStore(_ StoreReader) (*[]Diff, error) {
//	panic("implement me")
//}

// func (s *MockStore) GetVulnerabilityMetadata(id, namespace string) (*VulnerabilityMetadata, error) {
//	for _, meta := range s.Metadata {
//		if meta.ID == id && meta.Namespace == namespace {
//			return &meta, nil
//		}
//	}
//	return nil, nil
//}

// func (s *MockStore) GetAllVulnerabilityMetadata() (*[]VulnerabilityMetadata, error) {
//	var out []VulnerabilityMetadata
//	for _, v := range s.Metadata {
//		for _, vv := range v {
//			out = append(out, *vv)
//		}
//	}
//	return &out, nil
//}

func (s *MockStore) GetVulnerabilityMatchExclusion(id string) ([]VulnerabilityMatchExclusion, error) {
	if s.Exclusions == nil {
		return nil, nil
	}
	return filterE(s.Exclusions, func(v VulnerabilityMatchExclusion) (bool, error) {
		return v.ID == id, nil
	})
}

func (s *MockStore) Close() error {
	return nil
}

// func (s *MockStore) GetVulnerability(namespace, id string) ([]Vulnerability, error) {
//	var results []Vulnerability
//	//for _, vulns := range s.Data[namespace] {
//	//	for _, vuln := range vulns {
//	//		if vuln.ID == id {
//	//			results = append(results, vuln)
//	//		}
//	//	}
//	//}
//	for _, vuln := range s.Vulnerabilities {
//		if vuln.Namespace == namespace && vuln.ID == id {
//			results = append(results, toV5Vuln(vuln))
//		}
//	}
//	return results, nil
//}

// func (s *MockStore) SearchForVulnerabilities(namespace, name string) ([]Vulnerability, error) {
//	//namespaceMap := s.Data[namespace]
//	//if namespaceMap == nil {
//	//	return nil, nil
//	//}
//	//return namespaceMap[name], nil
//
//	var results []Vulnerability
//	for _, vuln := range s.Vulnerabilities {
//		if vuln.Namespace == namespace && vuln.ID == name {
//			results = append(results, toV5Vuln(vuln))
//		}
//	}
//	return results, nil
//}

// func (s *MockStore) GetAllVulnerabilities() (*[]Vulnerability, error) {
//	var out []Vulnerability
//	for _, v := range s.Vulnerabilities {
//		out = append(out, toV5Vuln(v))
//	}
//	return &out, nil
//}

// func (s *MockStore) GetVulnerabilityNamespaces() ([]string, error) {
//	//keys := make([]string, 0, len(s.Data))
//	//for k := range s.Data {
//	//	keys = append(keys, k)
//	//}
//
//	var keys []string
//	for _, vuln := range s.Vulnerabilities {
//		if slices.Contains(keys, vuln.Namespace) {
//			continue
//		}
//		keys = append(keys, vuln.Namespace)
//	}
//	return keys, nil
//}

// VulnerabilityMetadata returns the metadata associated with a vulnerability
func (s *MockStore) VulnerabilityMetadata(ref vulnerability.Reference) (*vulnerability.Metadata, error) {
	for _, meta := range s.Metadata {
		if meta.ID == ref.ID && meta.Namespace == ref.Namespace {
			return &meta, nil
		}
	}
	for _, vuln := range s.Vulnerabilities {
		if vuln.ID == ref.ID && vuln.Namespace == ref.Namespace {
			var meta *vulnerability.Metadata
			if m, ok := vuln.Reference.Internal.(vulnerability.Metadata); ok {
				meta = &m
			}
			if m, ok := vuln.Reference.Internal.(*vulnerability.Metadata); ok {
				meta = m
			}
			if meta != nil {
				if meta.ID != vuln.ID {
					meta.ID = vuln.ID
				}
				if meta.Namespace != vuln.Namespace {
					meta.Namespace = vuln.Namespace
				}
				return meta, nil
			}
		}
	}
	return nil, nil
}

func (s *MockStore) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	var out []vulnerability.Vulnerability
	// for namespace, data := range s.Data {
	//	for packageName, vulns := range data {
	//		for _, vuln := range vulns {
	//			if vuln.PackageName == "" {
	//				vuln.PackageName = packageName
	//			}
	//			if vuln.Namespace == "" {
	//				vuln.Namespace = namespace
	//			}
	//			v, err := NewVulnerability(vuln)
	//			if err != nil {
	//				panic(err)
	//			}
	//			out = append(out, *v)
	//		}
	//	}
	//}
	out = append(out, s.Vulnerabilities...)
	return filterE(out, func(v vulnerability.Vulnerability) (bool, error) {
		for _, c := range criteria {
			matches, err := c.MatchesVulnerability(v)
			if err != nil {
				return false, err
			}
			if !matches {
				return false, nil
			}
		}
		return true, nil
	})
}

func filterE[T any](out []T, keep func(v T) (bool, error)) ([]T, error) {
	for i := 0; i < len(out); i++ {
		ok, err := keep(out[i])
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out[:i], out[i+1:]...)
			i--
		}
	}
	return out, nil
}

//
//// toV5Vuln converts the given vulnerability to a v5.Vulnerability which some functions require
// func toV5Vuln(v vulnerability.Vulnerability) Vulnerability {
//	constraint, format := splitConstraint(v.Constraint)
//
//	var cpes []string
//	for _, c := range v.CPEs {
//		cpes = append(cpes, c.Attributes.BindToFmtString())
//	}
//
//	var advisories []Advisory
//	for _, adv := range v.Advisories {
//		advisories = append(advisories, Advisory{
//			ID:   adv.ID,
//			Link: adv.Link,
//		})
//	}
//
//	var packageQualifiers []v5qualifier.Qualifier
//	for _, q := range v.PackageQualifiers {
//		packageQualifiers = append(packageQualifiers, toV5Qualifier(q))
//	}
//
//	var relatedVulnerabilities []VulnerabilityReference
//	for _, rel := range v.RelatedVulnerabilities {
//		relatedVulnerabilities = append(relatedVulnerabilities, VulnerabilityReference{
//			ID:        rel.ID,
//			Namespace: rel.Namespace,
//		})
//	}
//
//	return Vulnerability{
//		ID:                     v.ID,
//		PackageName:            v.PackageName,
//		Namespace:              v.Namespace,
//		PackageQualifiers:      packageQualifiers,
//		VersionConstraint:      constraint,
//		VersionFormat:          format,
//		CPEs:                   cpes,
//		RelatedVulnerabilities: relatedVulnerabilities,
//		Fix: Fix{
//			Versions: v.Fix.Versions,
//			State:    FixState(v.Fix.State),
//		},
//		Advisories: advisories,
//	}
//}
//
// func toV5Qualifier(q qualifier.Qualifier) v5qualifier.Qualifier {
//	return v5Qualifier{
//		Qualifier: q,
//	}
//}
//
// type v5Qualifier struct {
//	qualifier.Qualifier
//}
//
// func (v v5Qualifier) String() string {
//	return fmt.Sprintf("<%s>", v.Qualifier)
//}
//
// func (v v5Qualifier) Parse() qualifier.Qualifier {
//	return v.Qualifier
//}
//
// var _ v5qualifier.Qualifier = (*v5Qualifier)(nil)
//
// func splitConstraint(constraint version.Constraint) (string, string) {
//	str := constraint.String()
//	parts := strings.Split(str, "(")
//	if len(parts) < 2 {
//		return str, ""
//	}
//	return strings.TrimSpace(parts[0]), strings.TrimSpace(strings.TrimRight(parts[1], ")"))
//}
