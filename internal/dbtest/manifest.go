package dbtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/OneOfOne/xxhash"
	"gopkg.in/yaml.v3"
)

const (
	// ConfigFilename is the name of the fixture config file (intent)
	ConfigFilename = "db.yaml"
	// LockFilename is the name of the fixture lock file (state)
	LockFilename = "db-lock.json"
)

// FixtureConfig represents the intent of what a fixture should contain (db.yaml).
// This file is human-edited and defines how the fixture was created.
type FixtureConfig struct {
	AutoGenerate bool                `yaml:"auto-generate"`
	Extractions  map[string][]string `yaml:"extractions"` // provider name -> patterns
}

// FixtureLock represents the state of a fixture (db.lock).
// This file is machine-generated and should never be manually edited.
type FixtureLock struct {
	ContentHash   string                   `json:"content_hash"`
	CreatedAt     time.Time                `json:"created_at"`
	RegeneratedAt *time.Time               `json:"regenerated_at,omitempty"`
	Providers     map[string]ProviderState `json:"providers"`
}

// ProviderState captures metadata from a vunnel provider at extraction time.
type ProviderState struct {
	VunnelVersion string    `json:"vunnel_version"` // from metadata.json processor field
	Timestamp     time.Time `json:"timestamp"`      // from metadata.json timestamp field
}

// FixtureStatus represents the high-level state of a fixture.
type FixtureStatus string

const (
	StatusOK           FixtureStatus = "ok"            // auto-generate=true, config/lock in sync, hash matches
	StatusContentDrift FixtureStatus = "content_drift" // auto-generate=true, files on disk don't match lock hash
	StatusConfigAhead  FixtureStatus = "config_ahead"  // auto-generate=true, config has extractions not in lock
	StatusManual       FixtureStatus = "manual"        // auto-generate=false
	StatusNoConfig     FixtureStatus = "no_config"     // no db.yaml
	StatusNoLock       FixtureStatus = "no_lock"       // db.yaml exists but no db.lock
)

// FixtureStatusDetail provides detailed information about a fixture's state.
type FixtureStatusDetail struct {
	Status        FixtureStatus
	ConfigExists  bool
	LockExists    bool
	AutoGenerate  bool
	ContentHash   string   // current hash of files on disk
	LockHash      string   // hash recorded in db.lock
	HashMatches   bool     // ContentHash == LockHash
	ConfigInSync  bool     // all config extractions have corresponding lock entries
	MissingInLock []string // providers in config but not in lock
}

// ReadConfig reads a FixtureConfig from the given fixture directory.
func ReadConfig(fixtureDir string) (*FixtureConfig, error) {
	path := filepath.Join(fixtureDir, ConfigFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config FixtureConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// Write writes the FixtureConfig to the given fixture directory.
func (c *FixtureConfig) Write(fixtureDir string) error {
	if err := os.MkdirAll(fixtureDir, 0755); err != nil {
		return fmt.Errorf("failed to create fixture directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	path := filepath.Join(fixtureDir, ConfigFilename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ReadLock reads a FixtureLock from the given fixture directory.
func ReadLock(fixtureDir string) (*FixtureLock, error) {
	path := filepath.Join(fixtureDir, LockFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read lock file: %w", err)
	}

	var lock FixtureLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse lock file: %w", err)
	}

	return &lock, nil
}

// Write writes the FixtureLock to the given fixture directory.
func (l *FixtureLock) Write(fixtureDir string) error {
	if err := os.MkdirAll(fixtureDir, 0755); err != nil {
		return fmt.Errorf("failed to create fixture directory: %w", err)
	}

	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lock: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(fixtureDir, LockFilename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write lock file: %w", err)
	}

	return nil
}

// ComputeFixtureContentHash computes an xxh64 hash of all fixture content,
// excluding db.yaml and db.lock files. The hash is deterministic based on
// file paths and contents, sorted alphabetically.
func ComputeFixtureContentHash(fixtureDir string) (string, error) {
	h := xxhash.New64()

	// collect all files, sorted for deterministic hashing
	var files []string
	err := filepath.Walk(fixtureDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// exclude config and lock files
		name := filepath.Base(path)
		if name == ConfigFilename || name == LockFilename {
			return nil
		}

		relPath, err := filepath.Rel(fixtureDir, path)
		if err != nil {
			return err
		}
		files = append(files, relPath)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to walk fixture directory: %w", err)
	}

	// sort for deterministic ordering
	sort.Strings(files)

	// hash each file's path and content
	for _, relPath := range files {
		if err := hashFile(h, fixtureDir, relPath); err != nil {
			return "", fmt.Errorf("failed to hash file %q: %w", relPath, err)
		}
	}

	return fmt.Sprintf("%016x", h.Sum64()), nil
}

func hashFile(h hash.Hash64, fixtureDir, relPath string) error {
	// hash the path (for deterministic ordering)
	if _, err := h.Write([]byte(relPath)); err != nil {
		return err
	}
	if _, err := h.Write([]byte{0}); err != nil { // null separator
		return err
	}

	// hash the content
	f, err := os.Open(filepath.Join(fixtureDir, relPath))
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if _, err := h.Write([]byte{0}); err != nil { // null separator
		return err
	}

	return nil
}

// GetFixtureStatus determines the current status of a fixture.
func GetFixtureStatus(fixtureDir string) (FixtureStatus, error) {
	detail, err := GetFixtureStatusDetail(fixtureDir)
	if err != nil {
		return "", err
	}
	return detail.Status, nil
}

// GetFixtureStatusDetail determines the detailed status of a fixture,
// including information about config/lock synchronization and content hashes.
func GetFixtureStatusDetail(fixtureDir string) (*FixtureStatusDetail, error) {
	detail := &FixtureStatusDetail{}

	// try to read config
	config, err := ReadConfig(fixtureDir)
	if err != nil {
		var pathErr *os.PathError
		if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) ||
			(errors.As(err, &pathErr) && os.IsNotExist(pathErr)) {
			detail.Status = StatusNoConfig
			return detail, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	detail.ConfigExists = true
	detail.AutoGenerate = config.AutoGenerate

	// if not auto-generate, it's manual
	if !config.AutoGenerate {
		detail.Status = StatusManual
		return detail, nil
	}

	// try to read lock
	lock, err := ReadLock(fixtureDir)
	if err != nil {
		var pathErr *os.PathError
		if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) ||
			(errors.As(err, &pathErr) && os.IsNotExist(pathErr)) {
			detail.Status = StatusNoLock
			return detail, nil
		}
		return nil, fmt.Errorf("failed to read lock: %w", err)
	}
	detail.LockExists = true
	detail.LockHash = lock.ContentHash

	// compute current content hash
	currentHash, err := ComputeFixtureContentHash(fixtureDir)
	if err != nil {
		return nil, fmt.Errorf("failed to compute content hash: %w", err)
	}
	detail.ContentHash = currentHash
	detail.HashMatches = currentHash == lock.ContentHash

	// check if config has extractions not in lock (config ahead)
	detail.ConfigInSync = true
	for provider := range config.Extractions {
		if _, exists := lock.Providers[provider]; !exists {
			detail.ConfigInSync = false
			detail.MissingInLock = append(detail.MissingInLock, provider)
		}
	}

	// determine final status
	switch {
	case !detail.ConfigInSync:
		// config has providers not recorded in lock
		detail.Status = StatusConfigAhead
	case !detail.HashMatches:
		// files on disk don't match what lock claims
		detail.Status = StatusContentDrift
	default:
		// everything matches
		detail.Status = StatusOK
	}

	return detail, nil
}
