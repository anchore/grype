package diff

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mholt/archives"

	"github.com/anchore/go-homedir"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
)

type ResolvedDB struct {
	Dir     string
	Info    DatabaseInfo
	Cleanup func()
}

// ResolveDB takes a user-provided value (URL, file path, or directory path) and returns
// a directory path containing a vulnerability.db file, suitable for passing to NewProviderDiffer.
// If defaultDir is non-empty and value is empty, defaultDir is used.
// The returned cleanup function should be called to remove any temporary directories created.
//
// Supported inputs:
//   - empty string: falls back to defaultDir
//   - URL (http/https): downloads the DB file to a temporary directory
//   - directory path: used as-is (must contain vulnerability.db)
//   - path to a .db file: uses the file's parent directory
//   - path to a DB archive (.tar.zst, .tar.gz, etc.): extracts and hydrates into a sibling
//     directory derived from the archive name (with .tar.* extension stripped)
func ResolveDB(value, defaultDir string) (ResolvedDB, error) {
	if value == "" {
		if defaultDir == "" {
			return ResolvedDB{}, fmt.Errorf("no database path or URL provided")
		}
		log.Infof("using default database directory: %s", defaultDir)
		return newResolvedDB(defaultDir, nil)
	}

	if isURL(value) {
		log.Infof("downloading database from: %s", value)
		dir, err := downloadDB(value)
		if err != nil {
			return ResolvedDB{}, err
		}
		cleanup := func() { _ = os.RemoveAll(dir) }

		return newResolvedDB(dir, cleanup)
	}

	expanded, err := homedir.Expand(value)
	if err != nil {
		return ResolvedDB{}, fmt.Errorf("unable to expand path %q: %w", value, err)
	}

	info, err := os.Stat(expanded)
	if err != nil {
		return ResolvedDB{}, fmt.Errorf("unable to stat %q: %w", expanded, err)
	}

	// case 1: it's already a directory containing a vulnerability.db
	if info.IsDir() {
		log.Infof("using database directory: %s", expanded)
		return newResolvedDB(expanded, nil)
	}

	// case 2: it's a raw vulnerability.db file; use its parent directory
	if strings.HasSuffix(expanded, ".db") {
		dir := filepath.Dir(expanded)
		log.Infof("using database file: %s", expanded)
		return newResolvedDB(dir, nil)
	}

	// case 3: it's a DB archive; extract and hydrate into a sibling directory
	return extractArchive(expanded)
}

func newResolvedDB(dir string, cleanup func()) (ResolvedDB, error) {
	log.Infof("hydrating database: %s", dir)

	hydrate := db.Hydrater()
	if err := hydrate(dir); err != nil {
		_ = os.RemoveAll(dir)
		return ResolvedDB{}, fmt.Errorf("failed to hydrate database: %w", err)
	}

	info, err := newDatabaseInfo(dir)
	if err != nil {
		return ResolvedDB{}, fmt.Errorf("failed to get old database info: %w", err)
	}

	return ResolvedDB{
		Dir:     dir,
		Info:    *info,
		Cleanup: cleanup,
	}, nil
}

var tarExtPattern = regexp.MustCompile(`\.tar(\.\w+)?$`)

// extractArchive extracts a DB archive into a sibling directory (archive name with
// .tar.* extension stripped), then runs hydration to create indexes. If the directory already
// exists with a vulnerability.db inside, it is reused
func extractArchive(archivePath string) (ResolvedDB, error) {
	destDir := tarExtPattern.ReplaceAllString(archivePath, "")
	if destDir == archivePath {
		return ResolvedDB{}, fmt.Errorf("unrecognized file type (not a .db file or supported archive): %s", archivePath)
	}

	// check if already extracted
	dbFilePath := filepath.Join(destDir, db.VulnerabilityDBFileName)
	if _, err := os.Stat(dbFilePath); err == nil {
		log.Infof("using previously extracted database: %s", destDir)
	} else {
		log.Infof("extracting database archive: %s", archivePath)

		if err := os.MkdirAll(destDir, 0o700); err != nil {
			return ResolvedDB{}, fmt.Errorf("failed to create extraction directory: %w", err)
		}

		if err := unarchiveDB(archivePath, destDir); err != nil {
			_ = os.RemoveAll(destDir)
			return ResolvedDB{}, fmt.Errorf("failed to extract archive %q: %w", archivePath, err)
		}
	}

	return newResolvedDB(destDir, nil)
}

// unarchiveDB extracts a DB archive to the given destination directory.
func unarchiveDB(source, destination string) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer log.CloseAndLogError(sourceFile, source)

	format, stream, err := archives.Identify(context.Background(), source, sourceFile)
	if err != nil {
		return fmt.Errorf("unable to identify archive format: %w", err)
	}

	extractor, ok := format.(archives.Extractor)
	if !ok {
		return fmt.Errorf("unable to extract DB file, format not supported: %s", source)
	}

	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}

	visitor := func(_ context.Context, file archives.FileInfo) error {
		if file.IsDir() || file.LinkTarget != "" {
			return nil
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer log.CloseAndLogError(fileReader, source+"/"+file.NameInArchive)

		filename := filepath.Clean(file.NameInArchive)

		outputFile, err := root.Create(filename)
		if err != nil {
			return err
		}
		defer log.CloseAndLogError(outputFile, source+"/"+filename)

		_, err = io.Copy(outputFile, fileReader)
		return err
	}

	return extractor.Extract(context.Background(), stream, visitor)
}

func isURL(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

// downloadDB downloads a vulnerability database from a URL to a temporary directory
// and returns the directory path. The caller is responsible for cleaning up the directory.
func downloadDB(url string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "grype-db-diff-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	dbPath := filepath.Join(tmpDir, db.VulnerabilityDBFileName)

	resp, err := http.Get(url) //nolint:gosec,bodyclose
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer log.CloseAndLogError(resp.Body, url)

	if resp.StatusCode != http.StatusOK {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to download from %s: bad status %s", url, resp.Status)
	}

	out, err := os.Create(dbPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer log.CloseAndLogError(out, dbPath)

	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to write database file: %w", err)
	}

	return tmpDir, nil
}
