package version

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	hashiVersion "github.com/anchore/go-version"
)

var latestAppVersionURL = struct {
	host string
	path string
}{
	// TODO: set me to release host/path before release
	host: "https://anchore.io",
	path: "/vulnscan/releases/latest/VERSION",
}

func IsUpdateAvailable() (bool, string, error) {
	currentVersionStr := FromBuild().Version
	currentVersion, err := hashiVersion.NewVersion(currentVersionStr)
	if err != nil {
		if currentVersionStr == valueNotProvided {
			// this is the default build arg and should be ignored (this is not an error case)
			return false, "", nil
		}
		return false, "", fmt.Errorf("failed to parse current application version: %w", err)
	}

	latestVersion, err := fetchLatestApplicationVersion()
	if err != nil {
		return false, "", err
	}

	if latestVersion.GreaterThan(currentVersion) {
		return true, latestVersion.String(), nil
	}

	return false, "", nil
}

func fetchLatestApplicationVersion() (*hashiVersion.Version, error) {
	req, err := http.NewRequest(http.MethodGet, latestAppVersionURL.host+latestAppVersionURL.path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for latest version: %w", err)
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d on fetching latest version: %s", resp.StatusCode, resp.Status)
	}

	versionBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read latest version: %w", err)
	}

	versionStr := strings.TrimSuffix(string(versionBytes), "\n")
	return hashiVersion.NewVersion(versionStr)
}
