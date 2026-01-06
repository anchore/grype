package provider

import (
	"os"
	"path/filepath"

	"github.com/OneOfOne/xxhash"
	"github.com/spf13/afero"

	"github.com/anchore/grype/internal/file"
)

type File struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Algorithm string `json:"algorithm"`
}

type Files []File

func NewFile(path string) (*File, error) {
	digest, err := file.HashFile(afero.NewOsFs(), path, xxhash.New64())
	if err != nil {
		return nil, err
	}

	return &File{
		Path:      path,
		Digest:    digest,
		Algorithm: "xxh64",
	}, nil
}

func NewFiles(paths ...string) (Files, error) {
	var files []File
	for _, path := range paths {
		input, err := NewFile(path)
		if err != nil {
			return nil, err
		}
		files = append(files, *input)
	}
	return files, nil
}

func (i Files) Paths() []string {
	var paths []string
	for _, input := range i {
		paths = append(paths, input.Path)
	}
	return paths
}

func NewFilesFromDir(dir string) (Files, error) {
	listing, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, f := range listing {
		if f.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(dir, f.Name()))
	}

	return NewFiles(paths...)
}
