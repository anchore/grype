package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/syft/syft"
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
	skopeoPath := filepath.Join(repoRoot(t), ".tool", "skopeo")
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

func getSyftSBOM(t testing.TB, image, from string, encoder sbom.FormatEncoder) string {
	src, err := syft.GetSource(context.Background(), image, syft.DefaultGetSourceConfig().WithSources(from))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, src.Close())
	})

	config := syft.DefaultCreateSBOMConfig()

	config.Search.Scope = source.SquashedScope
	// TODO: relationships are not verified at this time
	s, err := syft.CreateSBOM(context.Background(), src, config)
	require.NoError(t, err)
	require.NotNil(t, s)

	var buf bytes.Buffer

	err = encoder.Encode(&buf, *s)
	require.NoError(t, err)

	return buf.String()
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
