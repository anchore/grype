package cmd

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/version"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "updates grype",
	RunE:  runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(_ *cobra.Command, _ []string) error {
	fmt.Println("Checking for a newer version...")
	newerVersionAvailable, desiredVersion, err := checkLatestVersion()
	if err != nil {
		panic(err)
	}
	if newerVersionAvailable {
		compressed, err := downloadCompressed(desiredVersion)
		if err != nil {
			panic(err)
		}
		filePath := extractBinary(compressed)
		replaceBinary(filePath)
	} else {
		fmt.Println("You are already running the newest version available")
	}
	return nil
}

func extractBinary(fileName string) string {
	r, err := os.Open(fileName)
	if err != nil {
		defer os.Remove(fileName)
		panic(err)
	}
	tempDir, err := os.MkdirTemp("", "e_grype")
	fmt.Println("Extracting grype...")
	log.Infof("Extracting grype")
	log.Debugf("Extract destination is %s", tempDir)
	err = ExtractTarGz(r, tempDir)
	if err != nil {
		defer os.RemoveAll(tempDir)
		panic(err)
	}
	updatedGrypePath := fmt.Sprintf("%s/grype", tempDir)
	err = os.Chmod(updatedGrypePath, 0777)
	if err != nil {
		panic(err)
	}
	return updatedGrypePath
}

func replaceBinary(fileName string) {
	fmt.Println("Applying update...")
	log.Infof("Updating grype")

	executablePath, err := os.Executable()
	currentDir := filepath.Dir(executablePath)

	if err != nil {
		panic("Error getting current executable path")
	}
	updatedBytes, err := os.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	tempBinaryPath := fmt.Sprintf("%s/updatedGrype", currentDir)
	err = os.WriteFile(tempBinaryPath, updatedBytes, os.FileMode(0755))
	if err != nil {
		panic(err)
	}
	err = os.Rename(tempBinaryPath, executablePath)
	if err != nil {
		log.Errorf("Error while overwriting current executable: %s", err)
	}
	fmt.Println("Grype updated successfully! Run 'grype version' to get more info")
	log.Infof("Updated grype (%s) succesfully\n", executablePath)
}

func ExtractTarGz(gzipStream io.Reader, destination string) error {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Error("ExtractTarGz: NewReader failed")
		return err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Errorf("ExtractTarGz: Next() failed: %s", err.Error())
			return err
		}

		path := fmt.Sprintf("%s/%s", destination, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(path, 0755); err != nil {
				log.Errorf("ExtractTarGz: Mkdir() failed: %s", err.Error())
				return err
			}
		case tar.TypeReg:
			outFile, err := os.Create(path)
			if err != nil {
				log.Errorf("ExtractTarGz: Create() failed: %s", err.Error())
				return err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				log.Errorf("ExtractTarGz: Copy() failed: %s", err.Error())
				return err
			}
			outFile.Close()

		default:
			log.Errorf(
				"ExtractTarGz: uknown type: %s in %s",
				header.Typeflag,
				header.Name)
			return err
		}
	}
	return nil
}

func checkLatestVersion() (bool, string, error) {
	updateAvaliable, version, err := version.IsUpdateAvailable()
	if err != nil {
		log.Errorf("ERROR")
		fmt.Println(err)
		return false, "", err
	}
	if updateAvaliable {
		log.Infof("New version available v%s", version)
		return true, version, nil
	} else {
		log.Infof("No updates available")
	}
	return false, "", nil
}

func downloadCompressed(version string) (string, error) {
	var extension = "tar.gz"
	if runtime.GOOS == "windows" {
		extension = "zip"
	}
	f, err := os.CreateTemp("", "grype")
	log.Debugf("Created temporary file %s", f.Name())
	if err != nil {
		defer os.Remove(f.Name())
		panic(err)
	}

	var downloadUrlTemplate = "https://github.com/%s/%s/releases/download/v%s/grype_%s_%s_%s.%s"
	var downloadUrl = fmt.Sprintf(downloadUrlTemplate, "anchore", "grype", version, version, runtime.GOOS, runtime.GOARCH, extension)
	log.Infof("Downloading v%s", version)
	fmt.Printf("Downloading v%s...\n", version)
	resp, err := http.Get(downloadUrl)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(f, resp.Body)
	log.Debugf("Wrote %d bytes to %s", uint64(n), f.Name())
	if err != nil {
		panic(err)
	}
	return f.Name(), nil
}
