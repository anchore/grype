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
	Version      string `json:"version"`
	GitCommit    string `json:"git-commit"`
	GitTreeState string `json:"git-tree-state"`
	BuildDate    string `json:"build-date"`
	GoVersion    string `json:"go-version"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
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
