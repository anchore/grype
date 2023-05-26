package java

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nextlinux/griffon/griffon/pkg"
)

// MavenSearcher is the interface that wraps the GetMavenPackageBySha method.
type MavenSearcher interface {
	// GetMavenPackageBySha provides an interface for building a package from maven data based on a sha1 digest
	GetMavenPackageBySha(string) (*pkg.Package, error)
}

// mavenSearch implements the MavenSearcher interface
type mavenSearch struct {
	client  *http.Client
	baseURL string
}

type mavenAPIResponse struct {
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

	var res mavenAPIResponse
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

	return &pkg.Package{
		Name:     fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID),
		Version:  d.Version,
		Language: syftPkg.Java,
		Metadata: pkg.JavaMetadata{
			PomArtifactID: d.ArtifactID,
			PomGroupID:    d.GroupID,
		},
	}, nil
}
