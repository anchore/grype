package search

import (
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ Interface = &Client{}

type Resources struct {
	Store             v6.StoreReader
	AttributedMatcher match.MatcherType
}

type Criteria func(Resources) ([]match.Match, error)

type Interface interface {
	GetMetadata(id, namespace string) (*vulnerability.Metadata, error)
	ByCriteria(criteria ...Criteria) ([]match.Match, error)
}

type Client struct {
	resources Resources
}

func NewClient(store v6.StoreReader, matcherType match.MatcherType) *Client {
	return &Client{
		resources: Resources{
			Store:             store,
			AttributedMatcher: matcherType,
		},
	}
}

func (c Client) ByCriteria(criteria ...Criteria) ([]match.Match, error) {
	var matches []match.Match
	for _, criterion := range criteria {
		m, err := criterion(c.resources)
		if err != nil {
			return nil, err
		}
		matches = append(matches, m...)
	}
	return matches, nil
}

func (c Client) GetMetadata(id, namespace string) (*vulnerability.Metadata, error) {
	//TODO implement me
	panic("implement me")
}

//func init() {
//	c := NewClient(nil, "test")
//
//	p := pkg.Package{}
//	d := &distro.Distro{}
//
//}

//func ByCriteria(store vulnerability.Provider, d *distro.Distro, p pkg.Package, upstreamMatcher match.MatcherType, criteria ...Criteria) ([]match.Match, error) {
//	matches := make([]match.Match, 0)
//	for _, c := range criteria {
//		switch c {
//		case ByCPE:
//			m, err := ByPackageCPE(store, d, p, upstreamMatcher)
//			if errors.Is(err, ErrEmptyCPEMatch) {
//				log.Warnf("attempted CPE search on %s, which has no CPEs. Consider re-running with --add-cpes-if-none", p.Name)
//				continue
//			} else if err != nil {
//				log.Warnf("could not match by package CPE (package=%+v): %v", p, err)
//				continue
//			}
//			matches = append(matches, m...)
//		case ByLanguage:
//			m, err := ByPackageLanguage(store, d, p, upstreamMatcher)
//			if err != nil {
//				log.Warnf("could not match by package language (package=%+v): %v", p, err)
//				continue
//			}
//			matches = append(matches, m...)
//		case ByDistro:
//			m, err := ByPackageDistro(store, d, p, upstreamMatcher)
//			if err != nil {
//				log.Warnf("could not match by package distro (package=%+v): %v", p, err)
//				continue
//			}
//			matches = append(matches, m...)
//		}
//	}
//	return matches, nil
//}
