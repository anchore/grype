package testdb

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/provider"
)

var (
	pathSegmentReplacer = regexp.MustCompile(`[^-._a-zA-Z0-9+]`)
)

// CleanPath cleans paths matching vulnerability IDs to be filesystem safe
// Characters not matching the allowed set in pathSegmentReplacer are replaced with dash -
// this is applied on both writing in the result extractor and testing in globs
func CleanPath(path string) string {
	path = filepath.ToSlash(path)
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.Contains(part, "*") {
			starSplit := strings.Split(part, "*")
			for j := range starSplit {
				starSplit[j] = pathSegmentReplacer.ReplaceAllString(starSplit[j], "-")
			}
			parts[i] = strings.Join(starSplit, "*")
			continue
		}
		parts[i] = pathSegmentReplacer.ReplaceAllString(part, "-")
	}
	return strings.Join(parts, "/")
}

// BuildFromFlatFileDir builds a vulnerability database from a directory of vulnerability results
// if fileIncludes is non-empty, only files matching the provided substrings or globs will be included
//
//nolint:funlen
func BuildFromFlatFileDir(t *testing.T, buildTime time.Time, outputDir, inputDir string, fileIncludes ...string) {
	for i := range fileIncludes {
		fileIncludes[i] = prepareFileInclude(fileIncludes[i])
	}

	var states provider.States

	// rebuild only if the cache is older than the results
	if len(fileIncludes) == 0 && lastModifiedRecursive(t, outputDir).Before(lastModifiedRecursive(t, inputDir)) {
		return
	}

	include := func(string) bool { return true }
	if len(fileIncludes) > 0 {
		include = func(filename string) bool {
			filename = filepath.ToSlash(filename)
			filename = strings.ToLower(filename)
			for _, fileInclude := range fileIncludes {
				if doublestar.MatchUnvalidated(fileInclude, filename) {
					return true
				}
			}
			return false
		}
	}

	dirs, err := os.ReadDir(inputDir)
	require.NoError(t, err)
	for _, dir := range dirs {
		providerPath := filepath.Join(inputDir, dir.Name())
		checksums := bytes.Buffer{}
		for _, f := range readRecursive(t, providerPath, "results") {
			if !include(f) {
				continue
			}

			contents, err := os.ReadFile(filepath.Join(providerPath, f))
			require.NoError(t, err)

			// <hash> <two spaces> <file>
			_, err = fmt.Fprintf(&checksums, "%s  %s\n", xxh64(t, contents), f)
			require.NoError(t, err)
		}

		err = os.WriteFile(filepath.Join(providerPath, "checksums"), checksums.Bytes(), 0o600)
		require.NoError(t, err)

		metaVersion := "1"
		switch dir.Name() {
		case "nvd", "github":
			metaVersion = "2"
		case "ubuntu":
			metaVersion = "3"
		}

		metadata := `{
			"provider": "{provider}",
				"urls": [
				"https://{provider}"
			],
			"store": "flat-file",
			"timestamp": "{timestamp}",
			"version": {metadata_version},
			"distribution_version": 1,
			"processor": "vunnel@0.54.0",
			"listing": {
				"digest": "{checksum_file_digest}",
				"path": "checksums",
				"algorithm": "xxh64"
			},
			"schema": {
				"version": "{schema_version}",
				"url": "https://raw.githubusercontent.com/anchore/vunnel/main/schema/provider-workspace-state/schema-{schema_version}.json"
			},
			"stale": false
		}`
		metadata = strings.NewReplacer(
			"{provider}", dir.Name(),
			"{timestamp}", buildTime.Format(time.RFC3339),
			"{checksum_file_digest}", xxh64(t, checksums.Bytes()),
			"{schema_version}", "1.0.3",
			"{metadata_version}", metaVersion,
		).Replace(metadata)

		err = os.WriteFile(filepath.Join(providerPath, "metadata.json"), []byte(metadata), 0o600)
		require.NoError(t, err)

		// must create JSON and read it because this is the only way to populate unexported field resultFileStates
		state, err := provider.ReadState(filepath.Join(providerPath, "metadata.json"))
		require.NoError(t, err)

		states = append(states, *state)
	}

	cfg := db.BuildConfig{
		SchemaVersion:        6,
		Directory:            outputDir,
		States:               states,
		Timestamp:            buildTime,
		IncludeCPEParts:      []string{"o", "a", "h"},
		InferNVDFixVersions:  true,
		Hydrate:              true,
		FailOnMissingFixDate: false,
		BatchSize:            100,
	}

	err = db.Build(cfg)
	require.NoError(t, err)
}

func prepareFileInclude(s string) string {
	if !doublestar.ValidatePattern(s) {
		panic(fmt.Errorf("invalid glob: %s", s))
	}

	s = strings.ToLower(s)

	s = CleanPath(s)

	s = strings.ReplaceAll(s, "+", "\\+")

	// if the glob already specifies a glob, use it directly
	if strings.Contains(s, "**") {
		return s
	}
	// otherwise, assume it is probably a vuln id
	if !strings.HasSuffix(s, "*") && !strings.Contains(path.Base(s), ".") {
		s += "*"
	}
	if !strings.HasPrefix(s, "/") {
		s = "**/" + s
	}
	return s
}

func lastModifiedRecursive(t *testing.T, dir string) time.Time {
	latest := time.Time{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return latest
	}
	require.NoError(t, err)
	for _, entry := range entries {
		// check files and dirs last modified
		stat, err := os.Stat(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		if stat.ModTime().After(latest) {
			latest = stat.ModTime()
		}
		if entry.IsDir() {
			subdirModified := lastModifiedRecursive(t, filepath.Join(dir, entry.Name()))
			if subdirModified.After(latest) {
				latest = subdirModified
			}
			continue
		}
	}
	return latest
}

func xxh64(t *testing.T, contents []byte) string {
	h := xxhash.New64()
	_, err := h.Write(contents)
	require.NoError(t, err)
	hash := h.Sum(nil)
	out := fmt.Sprintf("%x", hash) // := base64.StdEncoding.EncodeToString(hash)
	return out
}

func readRecursive(t *testing.T, dir, subpath string) []string {
	var out []string
	files, err := os.ReadDir(filepath.Join(dir, subpath))
	require.NoError(t, err)
	for _, f := range files {
		childPath := filepath.Join(subpath, f.Name())
		if f.IsDir() {
			out = append(out, readRecursive(t, dir, filepath.Join(subpath, f.Name()))...)
		} else {
			out = append(out, childPath)
		}
	}
	return out
}
