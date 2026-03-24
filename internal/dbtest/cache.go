package dbtest

import (
	"os"
	"path/filepath"
)

const inputHashFileName = "input.xxh64"

// isCacheValid checks if the cache is valid by comparing the stored hash with the computed hash.
func isCacheValid(cacheDir, inputHash string) bool {
	data, err := os.ReadFile(filepath.Join(cacheDir, inputHashFileName))
	if err != nil {
		return false
	}
	return string(data) == inputHash
}

// writeStoredHash writes the input hash to the cache directory.
func writeStoredHash(cacheDir, hash string) error {
	return os.WriteFile(filepath.Join(cacheDir, inputHashFileName), []byte(hash), 0600)
}

// invalidateCache removes the entire cache directory.
func invalidateCache(cacheDir string) error {
	if _, err := os.Stat(cacheDir); err == nil {
		return os.RemoveAll(cacheDir)
	}
	return nil
}

// ensureCacheDir creates the cache directory if it doesn't exist.
func ensureCacheDir(cacheDir string) error {
	return os.MkdirAll(cacheDir, 0755)
}
