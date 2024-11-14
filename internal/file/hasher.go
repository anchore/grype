package file

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/OneOfOne/xxhash"
	"github.com/spf13/afero"
)

func ValidateByHash(fs afero.Fs, path, hashStr string) (bool, string, error) {
	var hasher hash.Hash
	var hashFn string
	switch {
	case strings.HasPrefix(hashStr, "sha256:"):
		hashFn = "sha256"
		hasher = sha256.New()
	case strings.HasPrefix(hashStr, "xxh64:"):
		hashFn = "xxh64"
		hasher = xxhash.New64()
	default:
		return false, "", fmt.Errorf("hasher not supported or specified (given: %s)", hashStr)
	}

	hashNoPrefix := strings.Split(hashStr, ":")[1]

	actualHash, err := HashFile(fs, path, hasher)
	if err != nil {
		return false, "", err
	}

	return actualHash == hashNoPrefix, hashFn + ":" + actualHash, nil
}

func HashFile(fs afero.Fs, path string, hasher hash.Hash) (string, error) {
	f, err := fs.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer f.Close()

	return HashReader(f, hasher)
}

func HashReader(reader io.Reader, hasher hash.Hash) (string, error) {
	if _, err := io.Copy(hasher, reader); err != nil {
		return "", fmt.Errorf("failed to hash reader: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
