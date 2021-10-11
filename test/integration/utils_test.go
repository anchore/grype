package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/syft/syft/format"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft"
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

	cmd := exec.Command("skopeo", "copy", "--override-os", "linux", sourceImage, destinationString)

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

func getSyftSBOM(t testing.TB, image string) string {
	src, cleanup, err := source.New(image, nil)
	if err != nil {
		t.Fatalf("can't get the source: %+v", err)
	}
	t.Cleanup(cleanup)

	scope := source.SquashedScope
	catalog, distro, err := syft.CatalogPackages(src, scope)

	by, err := syft.Encode(catalog, &src.Metadata, distro, format.JSONOption)
	if err != nil {
		t.Fatalf("can't get the formatted sbom: %+v", err)
	}

	return string(by)
}

func getMatchSet(matches match.Matches) *strset.Set {
	s := strset.New()
	for _, m := range matches.Sorted() {
		s.Add(fmt.Sprintf("%s-%s-%s-%s", m.Vulnerability.ID, m.Package.Name, m.Package.Version, string(m.Package.Type)))
	}
	return s
}
