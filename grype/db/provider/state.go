package provider

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

// data shape dictated by vunnel "provider workspace state" schema definition

type State struct {
	location            string
	root                string
	Provider            string    `json:"provider"`
	Version             int       `json:"version"`
	DistributionVersion int       `json:"distribution_version"`
	Processor           string    `json:"processor"`
	Schema              Schema    `json:"schema"`
	URLs                []string  `json:"urls"`
	Timestamp           time.Time `json:"timestamp"`
	Listing             *File     `json:"listing"`
	Store               string    `json:"store"`
	Stale               bool      `json:"stale"`
	resultFileStates    []File
}

type Schema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type States []State

func ReadState(location string) (*State, error) {
	by, err := os.ReadFile(location)
	if err != nil {
		return nil, err
	}

	var sd State
	if err := json.Unmarshal(by, &sd); err != nil {
		return nil, err
	}

	root := filepath.Dir(location)
	sd.root = root
	sd.location = location
	// we usually have a lot of records (depending on the source)
	sd.resultFileStates = make([]File, 0, 300000)

	start := time.Now()
	if sd.Listing != nil {
		algorithm := "xxh64" // sane default for performance

		// get extension from listing file
		extension := filepath.Ext(sd.Listing.Path)
		if extension != "" {
			algorithm = strings.TrimPrefix(extension, ".")
		}

		listingPath := filepath.Join(root, sd.Listing.Path)
		f, err := os.Open(listingPath)
		if err != nil {
			return nil, fmt.Errorf("unable to open listing file %q: %w", listingPath, err)
		}

		// note: bufio scanner is **much** faster than Fscan
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			index := strings.Index(line, "  ") // faster than strings.Split
			if index != -1 {
				sd.resultFileStates = append(sd.resultFileStates,
					File{
						Path:      line[index+2:],
						Digest:    line[:index],
						Algorithm: algorithm,
					},
				)
			}
		}
	}

	log.WithFields("duration", time.Since(start), "entries", len(sd.resultFileStates)).Trace("loaded result listing file")

	return &sd, nil
}

func (sd State) ResultPath(filename string) string {
	return filepath.Join(sd.root, filename)
}

func (sd State) ResultPaths() []string {
	var paths []string
	for _, p := range sd.resultFileStates {
		paths = append(paths, sd.ResultPath(p.Path))
	}
	return paths
}

func (sd State) Verify(workspaceRoots ...string) error {
	if sd.root != "" {
		workspaceRoots = append(workspaceRoots, sd.root)
	}
	for _, workspaceRoot := range workspaceRoots {
		for _, resultConfig := range sd.resultFileStates {
			workspace := NewWorkspaceFromExisting(workspaceRoot)
			path := filepath.Join(workspace.Path(), resultConfig.Path)

			log.WithFields("path", resultConfig.Path, "provider", sd.Provider).Trace("validating result file")

			matches, _, err := file.ValidateByHash(afero.NewOsFs(), path, resultConfig.Digest)
			if err != nil {
				return fmt.Errorf("unable to validate result file %q: %w", path, err)
			}
			if !matches {
				return fmt.Errorf("hash mismatch for result file %q", path)
			}
		}
	}

	return nil
}

func (s States) Names() []string {
	var names []string
	for _, state := range s {
		names = append(names, state.Provider)
	}
	return names
}

func (s States) EarliestTimestamp() (time.Time, error) {
	if len(s) == 0 {
		return time.Time{}, fmt.Errorf("cannot find earliest timestamp: no states provided")
	}

	// special case when there is exactly 1 state, return its timestamp even
	// if it is nvd, because otherwise quality gates that pull only nvd deterministically fail.
	if len(s) == 1 {
		return s[0].Timestamp, nil
	}

	var earliest time.Time
	for _, curState := range s {
		// the NVD api is constantly down, so we don't want to consider it for the earliest timestamp
		if curState.Provider == "nvd" {
			log.WithFields("provider", curState.Provider).Debug("not considering data age for provider")
			continue
		}
		if earliest.IsZero() {
			earliest = curState.Timestamp
			continue
		}
		if curState.Timestamp.Before(earliest) {
			earliest = curState.Timestamp
		}
	}

	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("unable to determine earliest timestamp")
	}

	log.WithFields("timestamp", earliest).Debug("earliest data timestamp")
	return earliest, nil
}
