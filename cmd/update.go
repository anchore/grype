package cmd

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/stereoscope"
)

var downloadURLTemplate = "https://github.com/anchore/grype/releases/download/v%s/grype_%s_%s_%s.%s"
var commandResultString = ""

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "updates grype",
	RunE:  runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(_ *cobra.Command, _ []string) error {
	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()
	if err != nil {
		return err
	}
	return eventLoop(
		startGrypeUpdate(),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func startGrypeUpdate() <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		importProgress := &progress.Manual{
			Total: 1,
		}
		stage := &progress.Stage{
			Current: "checking available versions",
		}
		downloadProgress := &progress.Manual{
			Total: 1,
		}
		aggregateProgress := progress.NewAggregator(progress.DefaultStrategy, downloadProgress, importProgress)

		bus.Publish(partybus.Event{
			Type: event.GrypeUpdate,
			Value: progress.StagedProgressable(&struct {
				progress.Stager
				progress.Progressable
			}{
				Stager:       progress.Stager(stage),
				Progressable: progress.Progressable(aggregateProgress),
			}),
		})

		defer downloadProgress.SetCompleted()
		defer importProgress.SetCompleted()

		newerVersionAvailable, desiredVersion, err := checkLatestVersion()

		if err != nil {
			log.Errorf("Error while checking for a newer version: %s", err)
			errs <- err
			return
		}
		if newerVersionAvailable {
			stage.Current = "downloading grype"
			compressed, err := downloadCompressed(desiredVersion)
			if err != nil {
				errs <- err
				return
			}
			stage.Current = "extracting grype"
			filePath, err := extractBinary(compressed)
			if err != nil {
				errs <- err
				return
			}
			stage.Current = "applying binary update"
			err = replaceBinary(filePath)
			if err != nil {
				errs <- err
				return
			}
			commandResultString = "Grype updated successfully! Run 'grype version' to get more info\n"
		} else {
			commandResultString = "You are already running the latest grype version\n"
		}
		stage.Current = "success"
		bus.Publish(partybus.Event{
			Type:  event.NonRootCommandFinished,
			Value: commandResultString,
		})
	}()
	return errs
}

func extractBinary(fileName string) (string, error) {
	r, err := os.Open(fileName)
	if err != nil {
		log.Errorf("Error while opening downloaded grype version: %s", err)
		defer os.Remove(fileName)
		return "", err
	}
	tempDir, err := os.MkdirTemp("", "e_grype")
	if err != nil {
		log.Errorf("Error while creating a temporary directory: %s", err)
		return "", err
	}
	log.Infof("Extracting grype")
	log.Debugf("Extract destination is %s", tempDir)
	err = ExtractTarGz(r, tempDir)
	if err != nil {
		defer os.RemoveAll(tempDir)
		return "", err
	}
	updatedGrypePath := fmt.Sprintf("%s/grype", tempDir)
	err = os.Chmod(updatedGrypePath, 0777)
	if err != nil {
		return "", err
	}
	return updatedGrypePath, nil
}

func replaceBinary(fileName string) error {
	log.Infof("Updating grype")

	executablePath, err := os.Executable()
	currentDir := filepath.Dir(executablePath)
	if err != nil {
		log.Errorf("Error while getting current executable path: %s", err)
		return err
	}

	updatedBytes, err := os.ReadFile(fileName)
	if err != nil {
		log.Errorf("Error while reading new grype binary: %s", err)
		return err
	}

	tempBinaryPath := fmt.Sprintf("%s/updatedGrype", currentDir)
	err = os.WriteFile(tempBinaryPath, updatedBytes, os.FileMode(0755))
	if err != nil {
		log.Errorf("Error while copying new binary: %s", err)
		return err
	}
	err = os.Rename(tempBinaryPath, executablePath)
	if err != nil {
		log.Errorf("Error while aplying new binary: %s", err)
		return err
	}
	log.Infof("Updated grype (%s) successfully\n", executablePath)
	return nil
}

func ExtractTarGz(gzipStream io.Reader, destination string) error {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Error("ExtractTarGz: NewReader failed")
		return err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
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
			for {
				_, err := io.CopyN(outFile, tarReader, 1024)
				if err != nil {
					if err == io.EOF {
						break
					}
					log.Errorf("ExtractTarGz: Copy() failed: %s", err.Error())
					return err
				}
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
		return false, "", err
	}
	if updateAvaliable {
		log.Infof("New version available v%s", version)
		return true, version, nil
	}
	log.Infof("No updates available")
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
		log.Errorf("Error while creating temporary file: %s", err)
		defer os.Remove(f.Name())
		return "", err
	}

	var downloadURL = fmt.Sprintf(downloadURLTemplate, version, version, runtime.GOOS, runtime.GOARCH, extension)
	_, err = url.Parse(downloadURL)
	if err != nil {
		log.Errorf("Request url is not correctly formatted: %s\n", err)
		return "", err
	}
	log.Infof("Downloading grype v%s", version)
	resp, err := http.Get(downloadURL) //nolint
	if err != nil {
		log.Errorf("Error while downloading grype: %s", err)
		return "", err
	}
	defer resp.Body.Close()
	n, err := io.Copy(f, resp.Body)
	log.Debugf("Wrote %d bytes to %s", uint64(n), f.Name())
	if err != nil {
		log.Errorf("Error while writing downloaded file to a temporary location: %s", err)
		defer os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
