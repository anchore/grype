package pkg

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// zarfLocationPrefix is added to a synthetic Location on every package extracted
// from a Zarf package, so consumers can resolve a finding back to the originating
// SBOM/artifact via the JSON output.
const zarfLocationPrefix = "zarf:"

const zarfInputPrefix = "zarf:"

// ZarfPackageMetadata holds context about the source Zarf package.
type ZarfPackageMetadata struct {
	Path string
}

func zarfProvider(userInput string, config ProviderConfig, applyChannel func(*distro.Distro) bool) ([]Package, Context, *sbom.SBOM, error) {
	if !strings.HasPrefix(userInput, zarfInputPrefix) {
		return nil, Context{}, nil, errDoesNotProvide
	}

	archivePath := strings.TrimPrefix(userInput, zarfInputPrefix)

	packages, s, err := readZarfPackage(archivePath, config, applyChannel)
	if err != nil {
		return nil, Context{}, nil, fmt.Errorf("failed to read Zarf package: %w", err)
	}

	ctx := Context{
		Source: &source.Description{
			Metadata: ZarfPackageMetadata{
				Path: archivePath,
			},
		},
	}

	return packages, ctx, s, nil
}

// readZarfPackage opens a Zarf .tar.zst archive, locates sboms.tar within it,
// and decodes each SBOM entry into a merged package list.
func readZarfPackage(archivePath string, config ProviderConfig, applyChannel func(*distro.Distro) bool) ([]Package, *sbom.SBOM, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open Zarf package %s: %w", archivePath, err)
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create zstd reader: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading Zarf archive: %w", err)
		}

		if hdr.Name == "sboms.tar" {
			return readSBOMsFromTar(tr, config, applyChannel)
		}
	}

	return nil, nil, fmt.Errorf("sboms.tar not found in Zarf package %s", archivePath)
}

// readSBOMsFromTar iterates over entries in sboms.tar, decoding each SBOM
// and merging all packages into a single result set.
func readSBOMsFromTar(r io.Reader, config ProviderConfig, applyChannel func(*distro.Distro) bool) ([]Package, *sbom.SBOM, error) {
	sbomTar := tar.NewReader(r)

	var allPackages []Package
	var mergedSBOM *sbom.SBOM

	for {
		hdr, err := sbomTar.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading sboms.tar: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		log.WithFields("entry", hdr.Name).Debug("reading SBOM from Zarf package")

		buf, err := io.ReadAll(sbomTar)
		if err != nil {
			log.WithFields("entry", hdr.Name, "error", err).Warn("skipping unreadable SBOM entry in Zarf package")
			continue
		}

		s, fmtID, err := readSBOM(bytes.NewReader(buf))
		if err != nil {
			log.WithFields("entry", hdr.Name, "error", err).Warn("skipping unreadable SBOM entry in Zarf package")
			continue
		}

		d, _ := distroFromSBOM(s, config, applyChannel)
		catalog := removePackagesByOverlap(s.Artifacts.Packages, s.Relationships, d)

		var enhancers []Enhancer
		if fmtID != syftjson.ID {
			enhancers = purlEnhancers(applyChannel)
		}

		packages := FromCollection(catalog, s.Relationships, config.SynthesisConfig, enhancers...)

		// annotate each package with provenance back to the originating SBOM, and
		// propagate the per-SBOM distro to packages that don't already have one
		// (e.g. syft-JSON SBOMs, where distro is at the SBOM level rather than per-PURL).
		annotatePackagesFromZarfSBOM(packages, s, hdr.Name, d)

		allPackages = append(allPackages, packages...)

		if mergedSBOM == nil {
			mergedSBOM = s
		} else {
			mergeSBOM(mergedSBOM, s)
		}
	}

	if len(allPackages) == 0 {
		return nil, nil, fmt.Errorf("no valid SBOMs found in Zarf package")
	}

	return allPackages, mergedSBOM, nil
}

// mergeSBOM adds artifacts from src into dst for downstream formatting.
func mergeSBOM(dst, src *sbom.SBOM) {
	for p := range src.Artifacts.Packages.Enumerate() {
		dst.Artifacts.Packages.Add(p)
	}
	dst.Relationships = append(dst.Relationships, src.Relationships...)
}

// annotatePackagesFromZarfSBOM adds a synthetic Location to each package pointing
// back to the originating SBOM inside the Zarf archive (preferring the SBOM's
// declared source name, falling back to the tar entry name), and propagates the
// per-SBOM distro to any package that does not already carry one.
func annotatePackagesFromZarfSBOM(packages []Package, s *sbom.SBOM, entryName string, d *distro.Distro) {
	identifier := s.Source.Name
	if identifier == "" {
		identifier = entryName
	}
	loc := file.NewLocation(zarfLocationPrefix + identifier)

	for i := range packages {
		packages[i].Locations.Add(loc)
		if packages[i].Distro == nil && d != nil {
			packages[i].Distro = d
		}
	}
}
