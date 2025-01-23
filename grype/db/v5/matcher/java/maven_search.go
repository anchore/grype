package java

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"golang.org/x/time/rate"

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
	client      *http.Client
	baseURL     string
	rateLimiter *rate.Limiter
}

// newMavenSearch creates a new mavenSearch instance with rate limiting
// rate is specified as 1 request per 300ms
func newMavenSearch(client *http.Client, baseURL string, rateLimit time.Duration) *mavenSearch {
	return &mavenSearch{
		client:      client,
		baseURL:     baseURL,
		rateLimiter: rate.NewLimiter(rate.Every(rateLimit), 1),
	}
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

func (ms *mavenSearch) GetMavenPackageBySha(ctx context.Context, sha1 string) (*pkg.Package, error) {
	if sha1 == "" {
		return nil, errors.New("empty sha1 digest")
	}
	if ms.baseURL == "" {
		return nil, errors.New("empty maven search URL")
	}
	if ms.rateLimiter == nil {
		return nil, errors.New("rate limiter not initialized")
	}
	if ms.client == nil {
		return nil, errors.New("HTTP client not initialized")
	}

	// Wait for rate limiter
	err := ms.rateLimiter.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ms.baseURL, nil)
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
