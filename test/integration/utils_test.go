package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const cacheDirRelativePath string = "./test-fixtures/cache"

func PullThroughImageCache(t testing.TB, imageName string) string {
	cacheDirectory, absErr := filepath.Abs(cacheDirRelativePath)
	if absErr != nil {
		t.Fatalf("could not get absolute path of cache directory %s; %v", cacheDirRelativePath, absErr)
	}

	mkdirError := os.MkdirAll(cacheDirectory, 0755)
	if mkdirError != nil {
		t.Fatalf("could not create cache directory %s; %v", cacheDirRelativePath, absErr)
	}

	re := regexp.MustCompile("[/:]")
	archiveFileName := fmt.Sprintf("%s.tar", re.ReplaceAllString(imageName, "-"))
	imageArchivePath := filepath.Join(cacheDirectory, archiveFileName)

	if _, err := os.Stat(imageArchivePath); os.IsNotExist(err) {
		t.Logf("Cache miss for image %s; copying to archive at %s", imageName, imageArchivePath)
		saveImage(t, imageName, imageArchivePath)
	}

	return imageArchivePath
}

func saveImage(t testing.TB, imageName string, destPath string) {
	sourceImage := fmt.Sprintf("docker://docker.io/%s", imageName)
	destinationString := fmt.Sprintf("docker-archive:%s", destPath)
	skopeoPath := filepath.Join(repoRoot(t), ".tmp", "skopeo")
	policyPath := filepath.Join(repoRoot(t), "test", "integration", "test-fixtures", "skopeo-policy.json")

	skopeoCommand := []string{
		"--policy", policyPath,
		"copy", "--override-os", "linux", sourceImage, destinationString,
	}

	cmd := exec.Command(skopeoPath, skopeoCommand...)

	out, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			t.Logf("Stderr: %s", exitError.Stderr)
		}
		t.Fatal(err)
	}

	t.Logf("Stdout: %s\n", out)
}

func getSyftSBOM(t testing.TB, image string, format sbom.Format) string {
	sourceInput, err := source.ParseInput(image, "")
	if err != nil {
		t.Fatalf("could not generate source input for packages command: %+v", err)
	}

	src, cleanup, err := source.New(*sourceInput, nil, nil)
	if err != nil {
		t.Fatalf("can't get the source: %+v", err)
	}
	t.Cleanup(cleanup)

	config := cataloger.DefaultConfig()
	config.Search.Scope = source.SquashedScope
	// TODO: relationships are not verified at this time
	catalog, _, distro, err := syft.CatalogPackages(src, config)

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    catalog,
			LinuxDistribution: distro,
		},
		Source: src.Metadata,
	}

	bytes, err := syft.Encode(s, format)
	if err != nil {
		t.Fatalf("presenter failed: %+v", err)
	}

	return string(bytes)
}

func getMatchSet(matches match.Matches) *strset.Set {
	s := strset.New()
	for _, m := range matches.Sorted() {
		s.Add(fmt.Sprintf("%s-%s-%s", m.Vulnerability.ID, m.Package.Name, m.Package.Version))
	}
	return s
}

func repoRoot(tb testing.TB) string {
	tb.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		tb.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		tb.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}
