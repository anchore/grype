package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/config"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
)

const integrationDir = "test/integration"

// integrationDBRef matches the pinned DB in a gate file's setups: the archive URL and its checksum
var integrationDBRef = regexp.MustCompile(`https://grype\.anchore\.io/databases/v6/[^"@]+@sha256:[0-9a-f]{64}`)

// integrationTasks run the two integration suites, both on the DB pinned in test/integration/gates:
//   - quality: grype built from this checkout against the latest grype release, scored against the labels in
//     anchore/claims. yardstick is installed from .binny.yaml on first use, and downloads and caches the DB itself.
//   - api: the Go tests in test/integration, run against grype's library from this checkout.
func integrationTasks() Task {
	return Task{
		Tasks: []Task{
			{
				Name:         "integration",
				Description:  "run every integration suite",
				Dependencies: Deps("integration:quality", "integration:api"),
			},
			{
				Name:        "integration:quality",
				Description: "run the quality gate (build grype, scan with it and the latest release, score against labels)",
				Run: func() {
					// built like the release (see .goreleaser.yaml), so the candidate differs from the reference only in code.
					// No VCS stamp: yardstick keys its scan cache by the binary's digest, so a change that
					// leaves the code alone (docs, CI, labels) reuses the last scans.
					Run("go build -buildvcs=false -tags "+buildTags+" -o "+integrationDir+"/bin/grype ./cmd/grype", run.Env("CGO_ENABLED", "0"))
					runIntegrationGates()
				},
			},
			{
				Name:        "integration:api",
				Description: "run the Go integration tests against grype's library",
				Run: func() {
					Run(`go test -v -tags=` + buildTags + ` ./` + integrationDir)
				},
			},
			{
				Name:        "integration:quality:score",
				Description: "re-score the last quality gate scans against the current labels, without scanning",
				Run: func() {
					runIntegrationGates("score")
				},
			},
			{
				Name:        "integration:update-db",
				Description: "pin both integration suites to the latest published DB",
				Run: func() {
					var listing []struct {
						Path     string `json:"path"`
						Checksum string `json:"checksum"`
					}
					lang.Throw(json.Unmarshal([]byte(Run("go run ./cmd/grype db list -o json", run.Quiet())), &listing))
					ref := "https://grype.anchore.io/databases/v6/" + listing[0].Path + "@" + listing[0].Checksum
					for _, gate := range file.FindAll(integrationDir + "/gates/*.yaml") {
						file.Write(gate, integrationDBRef.ReplaceAllString(file.Read(gate), ref))
					}
				},
			},
			{
				Name:        "integration:clean",
				Description: "remove the integration suites' grype build, scans and DB",
				RunsOn:      lang.List("clean"),
				Run: func() {
					file.Delete(integrationDir + "/bin")
					file.Delete(integrationDir + "/.yardstick")
					file.Delete(integrationDir + "/.cache")
				},
			},
		},
	}
}

// runIntegrationGates runs yardstick over every gate file, in test/integration so its .yardstick.yaml applies. Only
// yardstick runs there: Run installs it with binny first, which must run from the repo root to find .binny.yaml.
// The verdict is on stdout, which Run would otherwise only capture.
func runIntegrationGates(args ...string) {
	// yardstick shows progress only on a terminal, so without logs a CI run is silent until the verdict
	if config.CI {
		args = append(args, "-v")
	}
	for _, gate := range file.FindAll(integrationDir + "/gates/*.yaml") {
		args = append(args, strings.TrimPrefix(gate, integrationDir+"/"))
	}
	Run("yardstick", run.Args(args...), run.InDir(integrationDir), run.Stdout(os.Stdout))
}
