package provider

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OneOfOne/xxhash"
)

type Workspace struct {
	Root string
	Name string
}

func NewWorkspace(root, name string) Workspace {
	return Workspace{
		Root: root,
		Name: name,
	}
}

func NewWorkspaceFromExisting(workspacePath string) Workspace {
	return Workspace{
		Root: filepath.Dir(workspacePath),
		Name: filepath.Base(workspacePath),
	}
}

func (w Workspace) Path() string {
	return filepath.Join(w.Root, w.Name)
}

func (w Workspace) StatePath() string {
	return filepath.Join(w.Path(), "metadata.json")
}

func (w Workspace) InputPath() string {
	return filepath.Join(w.Path(), "input")
}

func (w Workspace) ResultsPath() string {
	return filepath.Join(w.Path(), "results")
}

func (w Workspace) ListingPath() string {
	return filepath.Join(w.ResultsPath(), "listing.xxh64")
}

func (w Workspace) ReadState() (*State, error) {
	return ReadState(w.StatePath())
}

// EnsureListingFile checks if a listing.xxh64 file exists in the results directory.
// If it doesn't exist, generates one by hashing all result files.
func (w Workspace) EnsureListingFile() error {
	listingPath := w.ListingPath()

	// check if listing file already exists
	if _, err := os.Stat(listingPath); err == nil {
		return nil
	}

	resultsDir := w.ResultsPath()

	// check if results directory exists
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		// no results directory, nothing to list
		return nil
	}

	// generate listing file
	return GenerateListingFile(resultsDir, listingPath)
}

// GenerateListingFile creates a listing.xxh64 file with hashes of all result files.
// Format: <hash>  <relative-path> (two spaces separator, matching vunnel format)
// Supports nested directory structures (e.g., results/debian@10/CVE-2024-1234.json).
func GenerateListingFile(resultsDir, listingPath string) error {
	// collect all result files recursively (excluding listing files)
	var files []string
	err := filepath.WalkDir(resultsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		// skip listing files
		if strings.HasSuffix(name, ".xxh64") || strings.HasSuffix(name, ".sha256") {
			return nil
		}
		// get path relative to resultsDir
		relPath, err := filepath.Rel(resultsDir, path)
		if err != nil {
			return err
		}
		files = append(files, relPath)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk results directory: %w", err)
	}

	// sort for determinism
	sort.Strings(files)

	// create listing file
	f, err := os.Create(listingPath)
	if err != nil {
		return fmt.Errorf("failed to create listing file: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, relPath := range files {
		filePath := filepath.Join(resultsDir, relPath)
		hash, err := HashFileXXH64(filePath)
		if err != nil {
			return fmt.Errorf("failed to hash file %q: %w", relPath, err)
		}

		// format: <hash>  results/<relative-path>
		// the path is relative to the provider directory
		listingPath := filepath.Join("results", relPath)
		if _, err := fmt.Fprintf(writer, "%s  %s\n", hash, listingPath); err != nil {
			return err
		}
	}

	return writer.Flush()
}

// HashFileXXH64 computes the xxhash64 of a file and returns it as a hex string.
func HashFileXXH64(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := xxhash.New64()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
