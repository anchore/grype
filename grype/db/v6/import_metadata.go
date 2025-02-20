package v6

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/OneOfOne/xxhash"
	"github.com/spf13/afero"

	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/schemaver"
)

const ImportMetadataFileName = "import.json"

type ImportMetadata struct {
	Digest string `json:"digest"`

	ClientVersion string `json:"client_version"`
}

func ReadImportMetadata(fs afero.Fs, dir string) (*ImportMetadata, error) {
	checksumsFilePath := filepath.Join(dir, ImportMetadataFileName)

	if _, err := fs.Stat(checksumsFilePath); os.IsNotExist(err) {
		return nil, nil
	}

	content, err := afero.ReadFile(fs, checksumsFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read import metadata file: %w", err)
	}

	if len(content) == 0 {
		return nil, nil
	}

	var doc ImportMetadata
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal import metadata: %w", err)
	}

	if !strings.HasPrefix(doc.Digest, "xxh64:") {
		return nil, fmt.Errorf("import metadata digest is not in the expected format")
	}

	return &doc, nil
}

func CalculateDBDigest(fs afero.Fs, dbFilePath string) (string, error) {
	digest, err := file.HashFile(fs, dbFilePath, xxhash.New64())
	if err != nil {
		return "", fmt.Errorf("failed to digest DB file: %w", err)
	}
	return fmt.Sprintf("xxh64:%s", digest), nil
}

func WriteImportMetadata(fs afero.Fs, dbDir string) (*ImportMetadata, error) {
	metadataFilePath := filepath.Join(dbDir, ImportMetadataFileName)
	f, err := fs.OpenFile(metadataFilePath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create import metadata file: %w", err)
	}
	defer f.Close()

	checksums, err := CalculateDBDigest(fs, filepath.Join(dbDir, VulnerabilityDBFileName))
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum for DB file: %w", err)
	}

	return writeImportMetadata(f, checksums)
}

func writeImportMetadata(writer io.Writer, checksums string) (*ImportMetadata, error) {
	if checksums == "" {
		return nil, fmt.Errorf("checksum is required")
	}

	if !strings.HasPrefix(checksums, "xxh64:") {
		return nil, fmt.Errorf("checksum missing algorithm prefix")
	}

	enc := json.NewEncoder(writer)
	enc.SetIndent("", " ")

	doc := ImportMetadata{
		Digest:        checksums,
		ClientVersion: schemaver.New(ModelVersion, Revision, Addition).String(),
	}

	return &doc, enc.Encode(doc)
}
