package commands

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/internal/log"
)

// DBBuilderCacheRestore extracts a provider workspace tar archive into the
// provider workspace root, optionally restricted to a subset of providers.
// This is the inverse of 'db-builder cache backup'.
func DBBuilderCacheRestore(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore provider workspace data from a cache tarball",
		Long: `Read the cache archive at --path and extract its contents into the
provider workspace root. Use --provider-name to restore only a subset and
--delete-existing to remove any pre-existing data for the restored
providers before extracting.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderCacheRestore(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderCacheRestore(opts *options.DatabaseBuild) error {
	if opts.Cache.Path == "" {
		return fmt.Errorf("--path is required")
	}

	providersDescr := "all"
	if len(opts.Provider.IncludeFilter) > 0 {
		providersDescr = fmt.Sprintf("%s", opts.Provider.IncludeFilter)
	}
	log.WithFields("providers", providersDescr).Info("restoring provider state")

	if err := os.MkdirAll(opts.Provider.Root, 0755); err != nil {
		return fmt.Errorf("failed to create provider root directory: %w", err)
	}

	allowableProviders := strset.New(opts.Provider.IncludeFilter...)
	restorableProviders, err := readProviderNamesFromTarGz(opts.Cache.Path)
	if err != nil {
		return err
	}

	selectedProviders := strset.New()
	for _, name := range restorableProviders {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}
		selectedProviders.Add(name)

		if opts.Cache.DeleteExisting {
			log.WithFields("provider", name).Info("deleting existing provider data")
			if err := deleteProviderCache(opts.Provider.Root, name); err != nil {
				return fmt.Errorf("failed to delete provider cache: %w", err)
			}
		} else {
			dir := filepath.Join(opts.Provider.Root, name)
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				log.WithFields("provider", name, "dir", dir).Debug("note: there is pre-existing provider data which could be overwritten by the restore operation")
			}
		}
	}

	log.WithFields("archive", opts.Cache.Path).Info("restoring provider data from backup")

	f, err := os.Open(opts.Cache.Path)
	if err != nil {
		return fmt.Errorf("failed to open cache archive: %w", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.Chdir(opts.Provider.Root); err != nil {
		return err
	}
	defer func(dir string) {
		if err := os.Chdir(dir); err != nil {
			log.Errorf("unable to restore directory: %w", err)
		}
	}(wd)

	if err := extractTarGz(f, selectedProviders); err != nil {
		return fmt.Errorf("failed to extract cache archive: %w", err)
	}

	log.WithFields("path", opts.Cache.Path).Info("provider data restored")
	return nil
}

func getProviderNameFromPath(path string) string {
	parts := strings.Split(filepath.Clean(path), string(os.PathSeparator))
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func readProviderNamesFromTarGz(tarPath string) ([]string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache archive: %w", err)
	}

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}

	providers := strset.New()
	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}
		provider := getProviderNameFromPath(header.Name)
		if provider != "" {
			providers.Add(provider)
		}
	}

	f.Close()
	return providers.List(), nil
}

func extractTarGz(reader io.Reader, selectedProviders *strset.Set) error {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}

	tr := tar.NewReader(gr)

	rootPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	var restoredAny bool
	fs := afero.NewOsFs()
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		provider := getProviderNameFromPath(header.Name)
		if !selectedProviders.Has(provider) {
			log.WithFields("path", header.Name, "provider", provider).Trace("skipping...")
			continue
		}
		restoredAny = true

		if err := processTarHeader(fs, rootPath, header, tr); err != nil {
			return err
		}
	}

	if !restoredAny {
		return fmt.Errorf("no provider data was restored")
	}
	return nil
}

func processTarHeader(fs afero.Fs, rootPath string, header *tar.Header, reader io.Reader) error {
	cleanedPath := cleanPathRelativeToRoot(rootPath, header.Name)
	if err := detectPathTraversal(rootPath, cleanedPath); err != nil {
		return err
	}
	log.WithFields("path", cleanedPath).Trace("extracting file")

	switch header.Typeflag {
	case tar.TypeDir:
		if err := fs.Mkdir(cleanedPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	case tar.TypeSymlink:
		if err := handleSymlink(fs, rootPath, cleanedPath, header.Linkname); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}
	case tar.TypeReg:
		if err := handleFile(fs, cleanedPath, reader); err != nil {
			return fmt.Errorf("failed to handle file: %w", err)
		}
	default:
		log.WithFields("name", cleanedPath, "type", header.Typeflag).Warn("unknown file type in backup archive")
	}
	return nil
}

func handleFile(fs afero.Fs, cleanedPath string, reader io.Reader) error {
	if cleanedPath == "" {
		return fmt.Errorf("empty path")
	}
	parentPath := filepath.Dir(cleanedPath)
	if parentPath != "" {
		if err := fs.MkdirAll(parentPath, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory %q for file %q: %w", parentPath, cleanedPath, err)
		}
	}
	outFile, err := fs.Create(cleanedPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	if err := safeCopy(outFile, reader); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}
	return nil
}

func handleSymlink(fs afero.Fs, rootPath, cleanedPath, linkName string) error {
	if err := detectLinkTraversal(rootPath, cleanedPath, linkName); err != nil {
		return err
	}

	linkReader, ok := fs.(afero.LinkReader)
	if !ok {
		return afero.ErrNoReadlink
	}

	if linkTarget, err := linkReader.ReadlinkIfPossible(cleanedPath); err == nil {
		if linkTarget == linkName {
			return nil
		}
		if err := fs.Remove(cleanedPath); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	linker, ok := fs.(afero.Linker)
	if !ok {
		return afero.ErrNoSymlink
	}

	if err := linker.SymlinkIfPossible(linkName, cleanedPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}
	return nil
}

func cleanPathRelativeToRoot(rootPath, path string) string {
	return filepath.Join(rootPath, filepath.Clean(path))
}

func detectLinkTraversal(rootPath, cleanedPath, linkTarget string) error {
	linkTarget = filepath.Clean(linkTarget)
	if filepath.IsAbs(linkTarget) {
		return detectPathTraversal(rootPath, linkTarget)
	}
	linkTarget = filepath.Join(filepath.Dir(cleanedPath), linkTarget)
	if !strings.HasPrefix(linkTarget, rootPath) {
		return fmt.Errorf("symlink points outside root: %s -> %s", cleanedPath, linkTarget)
	}
	return nil
}

func detectPathTraversal(rootPath, cleanedPath string) error {
	if cleanedPath == "" {
		return nil
	}
	if !strings.HasPrefix(cleanedPath, rootPath) {
		return fmt.Errorf("path traversal detected: %s", cleanedPath)
	}
	return nil
}

const (
	_  = iota
	kb = 1 << (10 * iota) //nolint:deadcode,unused
	mb                    //nolint:deadcode,unused
	gb
)

const perFileReadLimit = 25 * gb

// safeCopy limits the copy from the reader to defend against decompression
// bomb attacks during archive extraction.
func safeCopy(writer io.Writer, reader io.Reader) error {
	numBytes, err := io.Copy(writer, io.LimitReader(reader, perFileReadLimit))
	if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
		return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
	}
	return nil
}
