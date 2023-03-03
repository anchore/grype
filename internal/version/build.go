package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/anchore/grype/internal/log"
)

const valueNotProvided = "[not provided]"

// all variables here are provided as build-time arguments, with clear default values
var version = valueNotProvided
var gitCommit = valueNotProvided
var gitDescription = valueNotProvided
var buildDate = valueNotProvided
var platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

// Version defines the application version details (generally from build information)
type Version struct {
	Version        string `json:"version"`        // application semantic version
	SyftVersion    string `json:"syftVersion"`    // the version of syft being used by grype
	GitCommit      string `json:"gitCommit"`      // git SHA at build-time
	GitDescription string `json:"gitDescription"` // output of 'git describe --dirty --always --tags'
	BuildDate      string `json:"buildDate"`      // date of the build
	GoVersion      string `json:"goVersion"`      // go runtime version at build-time
	Compiler       string `json:"compiler"`       // compiler used at build-time
	Platform       string `json:"platform"`       // GOOS and GOARCH at build-time
}

func (v Version) isProductionBuild() bool {
	if strings.Contains(v.Version, "SNAPSHOT") || strings.Contains(v.Version, valueNotProvided) {
		return false
	}
	return true
}

// FromBuild provides all version details
func FromBuild() Version {
	actualSyftVersion, err := extractSyftVersion()
	if err != nil {
		// TODO: parameterize error
		log.Trace("unable to find syft version")
		actualSyftVersion = valueNotProvided
	}
	return Version{
		Version:        version,
		SyftVersion:    actualSyftVersion,
		GitCommit:      gitCommit,
		GitDescription: gitDescription,
		BuildDate:      buildDate,
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
		Platform:       platform,
	}
}

func extractSyftVersion() (string, error) {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("unable to find the buildinfo section of the binary (syft version is unknown)")
	}

	for _, d := range buildInfo.Deps {
		if d.Path == "github.com/anchore/syft" {
			return d.Version, nil
		}
	}

	return "", fmt.Errorf("unable to find 'github.com/anchore/syft' from the buildinfo section of the binary")
}
