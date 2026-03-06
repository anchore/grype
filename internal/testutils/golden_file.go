package testutils

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

const (
	TestDataDir       = "testdata"
	GoldenFileDirName = "snapshot"
	GoldenFileExt     = ".golden"
	GoldenFileDirPath = TestDataDir + string(filepath.Separator) + GoldenFileDirName
)

// dangerText wraps text in ANSI escape codes for reverse red to make it highly visible.
func dangerText(s string) string {
	return "\033[7;31m" + s + "\033[0m"
}

func GetGoldenFilePath(t *testing.T) string {
	t.Helper()
	// when using table-driven-tests, the `t.Name()` results in a string with slashes
	// which makes it impossible to reference in a filesystem, producing a "No such file or directory"
	filename := strings.ReplaceAll(t.Name(), "/", "_")
	return path.Join(GoldenFileDirPath, filename+GoldenFileExt)
}

func UpdateGoldenFileContents(t *testing.T, contents []byte) {
	t.Helper()

	goldenFilePath := GetGoldenFilePath(t)

	t.Log(dangerText("!!! UPDATING GOLDEN FILE !!!"), goldenFilePath)

	err := os.WriteFile(goldenFilePath, contents, 0600)
	if err != nil {
		t.Fatalf("could not update golden file (%s): %+v", goldenFilePath, err)
	}
}

func GetGoldenFileContents(t *testing.T) []byte {
	t.Helper()

	goldenPath := GetGoldenFilePath(t)
	if !fileOrDirExists(t, goldenPath) {
		t.Fatalf("golden file does not exist: %s", goldenPath)
	}
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("could not open file (%s): %+v", goldenPath, err)
	}
	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("could not read file (%s): %+v", goldenPath, err)
	}
	return bytes
}

func fileOrDirExists(t *testing.T, filename string) bool {
	t.Helper()
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
