package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
)

const qualityDir = "test/quality"

// qualityDBRef matches the pinned DB in a gate file's setups: the archive URL and its checksum
var qualityDBRef = regexp.MustCompile(`https://grype\.anchore\.io/databases/v6/[^"@]+@sha256:[0-9a-f]{64}`)

// qualityTasks run the quality gate: grype built from this checkout against the latest grype release, both on
// the DB pinned in test/quality/gates, scored against the labels in anchore/claims. yardstick is installed from
// .binny.yaml on first use, and downloads and caches the DB itself.
func qualityTasks() Task {
	return Task{
		Tasks: []Task{
			{
				Name:        "quality",
				Description: "run the quality gate (build grype, scan with it and the latest release, score against labels)",
				Run: func() {
					// built like the release (see .goreleaser.yaml), so the candidate differs from the reference only in code
					Run("go build -tags "+buildTags+" -o "+qualityDir+"/bin/grype ./cmd/grype", run.Env("CGO_ENABLED", "0"))
					runQualityGates()
				},
			},
			{
				Name:        "quality:score",
				Description: "re-score the last quality gate scans against the current labels, without scanning",
				Run: func() {
					runQualityGates("score")
				},
			},
			{
				Name:        "update-quality-gate-db",
				Description: "pin the quality gate to the latest published DB",
				Run: func() {
					var listing []struct {
						Path     string `json:"path"`
						Checksum string `json:"checksum"`
					}
					lang.Throw(json.Unmarshal([]byte(Run("go run ./cmd/grype db list -o json", run.Quiet())), &listing))
					ref := "https://grype.anchore.io/databases/v6/" + listing[0].Path + "@" + listing[0].Checksum
					for _, gate := range file.FindAll(qualityDir + "/gates/*.yaml") {
						file.Write(gate, qualityDBRef.ReplaceAllString(file.Read(gate), ref))
					}
				},
			},
			{
				Name:        "clean:quality",
				Description: "remove the quality gate's grype build and scans",
				RunsOn:      lang.List("clean"),
				Run: func() {
					file.Delete(qualityDir + "/bin")
					file.Delete(qualityDir + "/.yardstick")
				},
			},
		},
	}
}

// runQualityGates runs yardstick over every gate file, in test/quality so its .yardstick.yaml applies. Only
// yardstick runs there: Run installs it with binny first, which must run from the repo root to find .binny.yaml.
// The verdict is on stdout, which Run would otherwise only capture.
func runQualityGates(args ...string) {
	for _, gate := range file.FindAll(qualityDir + "/gates/*.yaml") {
		args = append(args, strings.TrimPrefix(gate, qualityDir+"/"))
	}
	Run("yardstick", run.Args(args...), run.InDir(qualityDir), run.Stdout(os.Stdout))
}
