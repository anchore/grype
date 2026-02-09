package dbtest

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/OneOfOne/xxhash"
)

const (
	inputHashFileName = "input.xxh64"
)

// computeInputHash walks all files in the fixture directory and computes a combined xxhash64.
// Files are processed in sorted order to ensure deterministic hashing.
func computeInputHash(fixtureDir string) (string, error) {
	hasher := xxhash.New64()

	var files []string
	err := filepath.Walk(fixtureDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	// sort files for deterministic hashing
	sort.Strings(files)

	for _, path := range files {
		// include the relative path in the hash so file renames are detected
		relPath, err := filepath.Rel(fixtureDir, path)
		if err != nil {
			return "", err
		}
		if _, err := hasher.Write([]byte(relPath)); err != nil {
			return "", err
		}

		f, err := os.Open(path)
		if err != nil {
			return "", err
		}

		if _, err := io.Copy(hasher, f); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// readStoredHash reads the stored input hash from the cache directory.
func readStoredHash(cacheDir string) (string, error) {
	hashPath := filepath.Join(cacheDir, inputHashFileName)
	data, err := os.ReadFile(hashPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// writeStoredHash writes the input hash to the cache directory.
func writeStoredHash(cacheDir, hash string) error {
	hashPath := filepath.Join(cacheDir, inputHashFileName)
	return os.WriteFile(hashPath, []byte(hash), 0644)
}

// isCacheValid checks if the cache is valid by comparing the stored hash with the computed hash.
func isCacheValid(cacheDir, inputHash string) bool {
	storedHash, err := readStoredHash(cacheDir)
	if err != nil {
		return false
	}
	return storedHash == inputHash
}

// invalidateCache removes all cached database files and the input hash file.
func invalidateCache(cacheDir string) error {
	// remove the entire cache directory if it exists
	if _, err := os.Stat(cacheDir); err == nil {
		if err := os.RemoveAll(cacheDir); err != nil {
			return err
		}
	}
	return nil
}

// ensureCacheDir creates the cache directory if it doesn't exist.
func ensureCacheDir(cacheDir string) error {
	return os.MkdirAll(cacheDir, 0755)
}
