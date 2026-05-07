package dbtest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RegenerateOptions configures the regeneration behavior.
type RegenerateOptions struct {
	VunnelRoot string // path to vunnel data directory
	Force      bool   // regenerate even if modified
	DryRun     bool   // only report what would be done
}

// RegenerateResult describes the outcome of a regeneration attempt.
type RegenerateResult struct {
	FixtureDir string
	Status     FixtureStatus
	Skipped    bool
	SkipReason string
	Error      error
}

// RegenerateFixture regenerates a single fixture from its config.
// The process is: check status -> delete fixture content -> replay extractions -> update lock.
func RegenerateFixture(fixtureDir string, opts RegenerateOptions) (*RegenerateResult, error) {
	result := &RegenerateResult{
		FixtureDir: fixtureDir,
	}

	// check status and decide whether to skip
	shouldSkip, err := checkRegenerationStatus(result, fixtureDir, opts)
	if err != nil {
		return result, err
	}
	if shouldSkip || opts.DryRun {
		return result, nil
	}

	// read config and existing lock
	config, existingLock, err := loadRegenerationConfig(fixtureDir)
	if err != nil {
		result.Error = err
		return result, err
	}

	// delete old content and replay extractions
	if err := deleteFixtureContent(fixtureDir); err != nil {
		result.Error = fmt.Errorf("failed to delete fixture content: %w", err)
		return result, result.Error
	}

	providerStates, err := replayExtractions(fixtureDir, config, opts.VunnelRoot)
	if err != nil {
		result.Error = err
		return result, err
	}

	// create and write new lock
	if err := createRegenerationLock(fixtureDir, existingLock, providerStates); err != nil {
		result.Error = err
		return result, err
	}

	return result, nil
}

func checkRegenerationStatus(result *RegenerateResult, fixtureDir string, opts RegenerateOptions) (bool, error) {
	status, err := GetFixtureStatus(fixtureDir)
	if err != nil {
		result.Error = fmt.Errorf("failed to get fixture status: %w", err)
		return true, result.Error
	}
	result.Status = status

	switch status {
	case StatusNoConfig:
		result.Skipped = true
		result.SkipReason = "no db.yaml config file"
		return true, nil

	case StatusManual:
		result.Skipped = true
		result.SkipReason = "marked as manual (auto-generate: false)"
		return true, nil

	case StatusContentDrift, StatusConfigAhead:
		if !opts.Force {
			result.Skipped = true
			if status == StatusContentDrift {
				result.SkipReason = "files on disk don't match lock hash (use --force to regenerate)"
			} else {
				result.SkipReason = "config has providers not in lock (use --force to regenerate)"
			}
			return true, nil
		}
	}

	return false, nil
}

func loadRegenerationConfig(fixtureDir string) (*FixtureConfig, *FixtureLock, error) {
	config, err := ReadConfig(fixtureDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}

	existingLock, _ := ReadLock(fixtureDir) // ignore error, may not exist
	return config, existingLock, nil
}

func replayExtractions(fixtureDir string, config *FixtureConfig, vunnelRoot string) (map[string]ProviderState, error) {
	extractor := NewFixtureExtractor(vunnelRoot)
	providerStates := make(map[string]ProviderState)

	providers := make([]string, 0, len(config.Extractions))
	for provider := range config.Extractions {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	for i, provider := range providers {
		state, err := extractProviderForRegeneration(extractor, fixtureDir, provider, config.Extractions[provider], i == 0, vunnelRoot)
		if err != nil {
			return nil, err
		}
		providerStates[provider] = state
	}

	return providerStates, nil
}

func extractProviderForRegeneration(extractor *FixtureExtractor, fixtureDir, provider string, patterns []string, isFirst bool, vunnelRoot string) (ProviderState, error) {
	builder := extractor.From(provider).Select(patterns...)

	var writeErr error
	if isFirst {
		writeErr = builder.writeFixtureOnly(fixtureDir, false)
	} else {
		writeErr = builder.writeFixtureOnly(fixtureDir, true)
	}

	if writeErr != nil {
		return ProviderState{}, fmt.Errorf("failed to extract from provider %q: %w", provider, writeErr)
	}

	state, err := readProviderState(vunnelRoot, provider)
	if err != nil {
		return ProviderState{}, fmt.Errorf("failed to read provider state for %q: %w", provider, err)
	}

	return state, nil
}

func createRegenerationLock(fixtureDir string, existingLock *FixtureLock, providerStates map[string]ProviderState) error {
	contentHash, err := ComputeFixtureContentHash(fixtureDir)
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}

	now := time.Now().UTC()
	lock := &FixtureLock{
		ContentHash:   contentHash,
		CreatedAt:     now,
		RegeneratedAt: &now,
		Providers:     providerStates,
	}

	if existingLock != nil {
		lock.CreatedAt = existingLock.CreatedAt
	}

	if err := lock.Write(fixtureDir); err != nil {
		return fmt.Errorf("failed to write lock: %w", err)
	}

	return nil
}

// deleteFixtureContent removes all fixture content except db.yaml.
func deleteFixtureContent(fixtureDir string) error {
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		// keep db.yaml
		if name == ConfigFilename {
			continue
		}

		path := filepath.Join(fixtureDir, name)
		if entry.IsDir() {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("failed to remove directory %q: %w", name, err)
			}
		} else {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove file %q: %w", name, err)
			}
		}
	}

	return nil
}

// DiscoverFixtures finds all fixture directories containing a db.yaml file
// under the given search roots.
func DiscoverFixtures(searchRoots ...string) ([]string, error) {
	var fixtures []string

	for _, root := range searchRoots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			if info.Name() == ConfigFilename {
				fixtures = append(fixtures, filepath.Dir(path))
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk %q: %w", root, err)
		}
	}

	return fixtures, nil
}

// RegenerateAll regenerates all fixtures found under the given search roots.
func RegenerateAll(searchRoots []string, opts RegenerateOptions) ([]RegenerateResult, error) {
	fixtures, err := DiscoverFixtures(searchRoots...)
	if err != nil {
		return nil, fmt.Errorf("failed to discover fixtures: %w", err)
	}

	var results []RegenerateResult
	for _, fixtureDir := range fixtures {
		result, err := RegenerateFixture(fixtureDir, opts)
		if result == nil {
			// should not happen, but handle defensively
			result = &RegenerateResult{
				FixtureDir: fixtureDir,
				Error:      err,
			}
		}
		results = append(results, *result)
	}

	return results, nil
}
