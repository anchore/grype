package java

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// MavenSearcher is the interface that wraps the GetMavenPackageBySha method.
type MavenSearcher interface {
	// GetMavenPackageBySha provides an interface for building a package from maven data based on a sha1 digest
	GetMavenPackageBySha(context.Context, string) (*pkg.Package, error)
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

func (ms *mavenSearch) GetMavenPackageBySha(context context.Context, sha1 string) (*pkg.Package, error) {
	resultChan := make(chan *pkg.Package, 1)
	errChan := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, ms.baseURL, nil)
		if err != nil {
			errChan <- fmt.Errorf("unable to initialize HTTP client: %w", err)
			return
		}

		q := req.URL.Query()
		q.Set("q", fmt.Sprintf(sha1Query, sha1))
		q.Set("rows", "1")
		q.Set("wt", "json")
		req.URL.RawQuery = q.Encode()

		resp, err := ms.client.Do(req)
		if err != nil {
			errChan <- fmt.Errorf("sha1 search error: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			errChan <- fmt.Errorf("status %s from %s", resp.Status, req.URL.String())
			return
		}

		var res mavenAPIResponse
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			errChan <- fmt.Errorf("json decode error: %w", err)
			return
		}

		if len(res.Response.Docs) == 0 {
			errChan <- fmt.Errorf("digest %s: %w", sha1, errors.New("no artifact found"))
			return
		}

		// artifacts might have the same SHA-1 digests.
		// e.g. "javax.servlet:jstl" and "jstl:jstl"
		docs := res.Response.Docs
		sort.Slice(docs, func(i, j int) bool {
			return docs[i].ID < docs[j].ID
		})
		d := docs[0]

		resultChan <- &pkg.Package{
			Name:     fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID),
			Version:  d.Version,
			Language: syftPkg.Java,
			Metadata: pkg.JavaMetadata{
				PomArtifactID: d.ArtifactID,
				PomGroupID:    d.GroupID,
			},
		}
	}()

	select {
	case <-context.Done():
		// The context was canceled or its deadline was exceeded
		return nil, context.Err()
	case res := <-resultChan:
		// The work finished before the context was done
		return res, nil
	case err := <-errChan:
		// There was an error getting the package
		return nil, err
	}
}
