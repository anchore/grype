package java

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"net/http"
	"sort"
)

const (
	defaultBaseURL = "https://search.maven.org/solrsearch/select"
	sha1Query      = `1:"%s"`
)

type Matcher struct {
	SearchMavenUpstream bool
	MavenSearcher
}

// MavenSearcher is the interface that wraps the GetMavenPackageBySha method.
type MavenSearcher interface {
	// GetMavenPackageBySha provides an interface for building a package from maven data based on a sha1 digest
	GetMavenPackageBySha(string) (*pkg.Package, error)
}

type mavenSearch struct {
	client  *http.Client
	baseURL string
}

type mavenApiResposne struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID           string `json:"id"`
			GroupID      string `json:"g"`
			ArtifactID   string `json:"a"`
			Version      string `json:"v"`
			P            string `json:"p"`
			VersionCount int    `json:"versionCount"`
		} `json:"docs"`
	} `json:"response"`
}

func (ms *mavenSearch) GetMavenPackageBySha(sha1 string) (*pkg.Package, error) {
	req, err := http.NewRequest(http.MethodGet, ms.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(sha1Query, sha1))
	q.Set("rows", "1")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := ms.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sha1 search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res mavenApiResposne
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return nil, fmt.Errorf("digest %s: %w", sha1, errors.New("no artifact found"))
	}

	// artifacts might have the same SHA-1 digests.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].ID < docs[j].ID
	})
	d := docs[0]

	// TODO: Syft java package construction from Pom Data
	return &pkg.Package{
		Name:    d.ArtifactID,
		Version: d.Version,
	}, nil
}

type MatcherConfig struct {
	SearchMavenUpstream bool
}

func NewJavaMatcher(matcherConfig MatcherConfig) *Matcher {
	return &Matcher{
		matcherConfig.SearchMavenUpstream,
		&mavenSearch{
			client:  http.DefaultClient,
			baseURL: defaultBaseURL,
		},
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.JavaMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	return search.ByCriteria(store, d, p, m.Type(), search.CommonCriteria...)
}
