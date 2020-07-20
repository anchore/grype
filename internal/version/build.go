package version

import (
	"fmt"
	"runtime"
)

const valueNotProvided = "[not provided]"

var version = valueNotProvided
var gitCommit = valueNotProvided
var gitTreeState = valueNotProvided
var buildDate = valueNotProvided
var platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

type Version struct {
	Version      string
	GitCommit    string
	GitTreeState string
	BuildDate    string
	GoVersion    string
	Compiler     string
	Platform     string
}

func FromBuild() Version {
	return Version{
		Version:      version,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     platform,
	}
}
