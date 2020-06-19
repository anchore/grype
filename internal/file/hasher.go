package file

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/spf13/afero"
)

func ValidateByHash(fs afero.Fs, path, hashStr string) (bool, error) {
	var hasher hash.Hash
	switch {
	case strings.HasPrefix(hashStr, "sha256:"):
		hasher = sha256.New()
	default:
		return false, fmt.Errorf("hasher not supported or specified (given: %s)", hashStr)
	}

	hashNoPrefix := strings.Split(hashStr, ":")[1]

	actualHash, err := HashFile(fs, path, hasher)
	if err != nil {
		return false, err
	}

	return actualHash == hashNoPrefix, nil
}

func HashFile(fs afero.Fs, path string, hasher hash.Hash) (string, error) {
	f, err := fs.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer f.Close()

	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("failed to hash file '%s': %w", path, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
