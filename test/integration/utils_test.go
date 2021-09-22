package integration

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/presenter/packages"
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

	presenter := packages.Presenter(packages.JSONPresenterOption, packages.PresenterConfig{
		SourceMetadata: src.Metadata,
		Catalog:        catalog,
		Distro:         distro,
		Scope:          scope,
	})

	var buf bytes.Buffer
	if err := presenter.Present(bufio.NewWriter(&buf)); err != nil {
		t.Fatalf("presenter failed: %+v", err)
	}

	return buf.String()
}
