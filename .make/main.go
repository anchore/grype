package main

import (
	"fmt"
	"os"
	"strings"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/log"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

const (
	project    = "grype"
	snapshotBn = "snapshot" // goreleaser dist dir
)

func main() {
	Makefile(
		golint.Tasks(golint.SkipTests()),
		gotest.Tasks(
			gotest.CoverageThreshold(47),
			// excludes both anchore/grype/test/** and anchore/grype/internal/test/**
			gotest.ExcludeGlob("**/test/**"),
		),
		goreleaser.Tasks(),

		buildTask(),
		integrationTask(),
		cliTask(),
		qualityTask(),

		generateTask(),
		updateOSVModelTask(),
		checkJSONSchemaDriftTask(),
		checkDBSchemaDriftTask(),
		checkSyftVersionIsReleaseTask(),

		installTestTasks(),
		fingerprintsTask(),

		fixturesTasks(),
		updateQualityGateDBTask(),

		showTestImageCacheTask(),
		cleanCacheTask(),
	)
}

// buildTask runs `goreleaser build --single-target` to produce a local binary
// fast. go-make v0.4.0's snapshot:single-target task is broken (it invokes
// `goreleaser release --single-target`, which is rejected by goreleaser), so
// we re-implement single-target builds here mirroring goreleaser.SnapshotTasks'
// config-injection pattern.
func buildTask() Task {
	return Task{
		Name:         "build",
		Description:  "build a single-target snapshot binary",
		Dependencies: Deps("release:dependencies"),
		Run: func() {
			file.Require(".goreleaser.yaml")
			file.WithTempDir(func(tempDir string) {
				cfg := tempDir + "/.goreleaser.yaml"
				content := file.Read(".goreleaser.yaml")
				if !file.Contains(".goreleaser.yaml", "dist:") {
					content += "\ndist: " + snapshotBn + "\n"
				}
				file.Write(cfg, content)
				Run(fmt.Sprintf("goreleaser build --clean --snapshot --single-target --config=%s", cfg))
			})
		},
	}
}

// integrationTask runs the integration test suite plus a quick race-detector
// smoke test of the CLI against alpine:latest.
func integrationTask() Task {
	return Task{
		Name:        "integration",
		Description: "run integration tests",
		RunsOn:      lang.List("test"),
		Run: func() {
			Run(`go test -v ./test/integration`)
			// update database outside race detector, since doing so with
			// race detector on is very slow
			Run(fmt.Sprintf(`go run ./cmd/%s db update`, project))
			// exercise most of the CLI with the data race detector enabled
			Run(fmt.Sprintf(`go run -race ./cmd/%s alpine:latest`, project))
		},
	}
}

// cliTask runs the CLI test suite against the snapshot binary. When
// GRYPE_SNAPSHOT_PREBUILT is set and the binary exists (as in CI after the
// snapshot artifact is restored), it skips rebuilding.
func cliTask() Task {
	return Task{
		Name:        "cli",
		Description: "run CLI tests",
		RunsOn:      lang.List("test"),
		Run: func() {
			ensureSnapshotBinary()
			Run(`go test -count=1 -timeout=15m -v ./test/cli`)
		},
	}
}

// ensureSnapshotBinary builds a snapshot if one isn't already present. In CI we
// set GRYPE_SNAPSHOT_PREBUILT=true so a snapshot artifact restored from cache
// isn't rebuilt; locally we always rebuild so code changes take effect.
func ensureSnapshotBinary() {
	if os.Getenv("GRYPE_SNAPSHOT_PREBUILT") != "" {
		// CI path: trust the restored artifact, just verify it exists.
		matches := file.FindAll(fmt.Sprintf("%s/*/%s", snapshotBn, project))
		if len(matches) > 0 {
			log.Info("using prebuilt snapshot binary: %s", matches[0])
			return
		}
		log.Info("GRYPE_SNAPSHOT_PREBUILT set but no binary found; rebuilding")
	}
	Run(`go run -C .make . snapshot:single-target`)
}

func qualityTask() Task {
	return Task{
		Name:        "quality",
		Description: "run quality tests",
		Run: func() {
			file.InDir("test/quality", func() { Run("make") })
		},
	}
}

// generateTask groups all code-generation entry points. Each sub-task can be
// invoked directly (e.g. `make generate:json-schema`).
func generateTask() Task {
	return Task{
		Name:        "generate",
		Description: "run code and data generation tasks",
		Dependencies: Deps(
			"generate:json-schema",
			"generate:db-schema",
			"generate:codename-data",
			"generate:osv-model",
		),
		Tasks: []Task{
			{
				Name:        "generate:json-schema",
				Description: "generate a new JSON schema",
				Run: func() {
					// re-generate package metadata
					file.InDir("grype/internal", func() { Run("go generate") })
					// generate the JSON schema for the CLI output
					file.InDir("cmd/grype/cli/commands/internal/jsonschema", func() { Run("go run .") })
				},
			},
			{
				Name:        "generate:db-schema",
				Description: "generate database blob JSON schemas",
				Run: func() {
					file.InDir("grype/db/v6/schema", func() { Run("go run .") })
				},
			},
			{
				Name:         "generate:codename-data",
				Description:  "generate OS codename lookup data",
				Dependencies: Deps("format"),
				Run: func() {
					Run("go generate ./grype/db")
				},
			},
			{
				Name: "generate:osv-model",
				Description: "regenerate the OSV model from the pinned upstream JSON schema " +
					"(use `update:osv-model` to also fetch latest from github.com/ossf/osv-schema)",
				Run: func() {
					Run("go generate ./grype/db/internal/provider/unmarshal/osvmodel/...")
				},
			},
		},
	}
}

// checkJSONSchemaDriftTask verifies the committed JSON schema matches what
// regeneration would produce. Fails if uncommitted changes exist (so the diff
// is unambiguous) or if regeneration produced changes.
func checkJSONSchemaDriftTask() Task {
	return Task{
		Name:        "check-json-schema-drift",
		Description: "ensure there is no drift between the JSON schema and the code",
		Run: func() {
			requireCleanWorktree("uncommitted changes; commit them before running this check")
			Run("go run -C .make . generate:json-schema")
			requireCleanWorktree("JSON schema is out of date; run 'make generate:json-schema' and commit")
		},
	}
}

func checkDBSchemaDriftTask() Task {
	return Task{
		Name:        "check-db-schema-drift",
		Description: "ensure there is no drift between the database blob schemas and the code",
		Run: func() {
			requireCleanWorktree("uncommitted changes; commit them before running this check")
			Run("go run -C .make . generate:db-schema")
			if !worktreeClean() {
				log.Error(fmt.Errorf("database blob schemas have uncommitted changes"))
				// surface the diff so CI logs show what drifted
				Run("git status --porcelain")
				Run("git diff schema/grype/db/")
				lang.Throw(fmt.Errorf("database blob schemas are out of date; run 'make generate:db-schema' and commit"))
			}
			log.Info("Database blob schemas are up to date")
		},
	}
}

// updateOSVModelTask fetches the latest v1 OSV schema from upstream
// (github.com/ossf/osv-schema), writes schema-v1.json + schema-v1.tag, and
// regenerates vulnerability_generated.go. This is the cron-driven update
// counterpart to the offline `generate:osv-model`. Producing a diff is the
// expected outcome when upstream has moved; oss-release wraps this task to
// open a PR with that diff.
func updateOSVModelTask() Task {
	return Task{
		Name:        "update:osv-model",
		Description: "fetch latest v1 OSV schema from github.com/ossf/osv-schema and regenerate the model",
		Run: func() {
			file.InDir("grype/db/internal/provider/unmarshal/osvmodel/generate", func() {
				Run("go run . --pull")
			})
		},
	}
}

// checkSyftVersionIsReleaseTask ensures go.mod pins a released syft tag (not a
// commit hash or pseudo-version). Gates releases so we don't ship grype against
// an unreleased syft.
func checkSyftVersionIsReleaseTask() Task {
	return Task{
		Name:        "check-syft-version-is-release",
		Description: "ensure the syft pin in go.mod is a released version",
		Run: func() {
			out := Run(`bash -c "grep -E 'github.com/anchore/syft' go.mod | awk '{print $NF}'"`)
			version := strings.TrimSpace(out)
			// matches "vMAJOR.MINOR.PATCH" (any digits); rejects pseudo-versions like v0.0.0-20240101...
			if !regexpMatchSemverTag(version) {
				lang.Throw(fmt.Errorf("syft version in go.mod is not a released tag: %s", version))
			}
			log.Info("syft version in go.mod is a release version: %s", version)
		},
	}
}

// installTestTasks runs install.sh acceptance tests inside docker containers
// (driven by test/install/Makefile).
func installTestTasks() Task {
	return Task{
		Tasks: []Task{
			{
				Name:        "install-test",
				Description: "run install.sh acceptance tests",
				Run: func() {
					file.InDir("test/install", func() { Run("make") })
				},
			},
			{
				Name:        "install-test-cache-save",
				Description: "save install.sh test image cache",
				Run: func() {
					file.InDir("test/install", func() { Run("make save") })
				},
			},
			{
				Name:        "install-test-cache-load",
				Description: "load install.sh test image cache",
				Run: func() {
					file.InDir("test/install", func() { Run("make load") })
				},
			},
			{
				Name:        "install-test-ci-mac",
				Description: "run install.sh acceptance tests on mac (CI)",
				Run: func() {
					file.InDir("test/install", func() { Run("make ci-test-mac") })
				},
			},
		},
	}
}

// fingerprintsTask regenerates cache.fingerprint files for the three test
// suites that participate in CI caching. Not auto-discovered by
// gotest.FixtureTasks because test/install/Makefile lives outside the
// testdata/test-fixtures convention.
func fingerprintsTask() Task {
	return Task{
		Name:        "fingerprints",
		Description: "generate test fixture cache fingerprints",
		Run: func() {
			for _, dir := range []string{
				"test/integration/testdata",
				"test/install",
				"test/cli/testdata",
			} {
				file.InDir(dir, func() { Run("make cache.fingerprint") })
			}
		},
	}
}

// fixturesTasks wraps the dbtest fixture manager CLI.
func fixturesTasks() Task {
	const mgr = "go run ./internal/dbtest/cmd/manager"
	return Task{
		Tasks: []Task{
			{
				Name:        "fixture-status",
				Description: "show status of all database test fixtures",
				Run:         func() { Run(mgr + " status") },
			},
			{
				Name:        "regenerate-fixtures",
				Description: "regenerate all reproducible database test fixtures from vunnel cache",
				Run: func() {
					Run(mgr + " regenerate " + vunnelDataFlag())
				},
			},
			{
				Name:        "regenerate-fixtures-dry-run",
				Description: "show what fixtures would be regenerated (dry run)",
				Run: func() {
					Run(mgr + " regenerate " + vunnelDataFlag() + " --dry-run")
				},
			},
		},
	}
}

func vunnelDataFlag() string {
	data := os.Getenv("VUNNEL_DATA")
	if data == "" {
		data = "~/vunnel/data"
	}
	return "--vunnel-data " + data
}

// updateQualityGateDBTask pins the test DB used by the quality test suite to
// whatever is currently latest in the v6 distribution. Output goes to
// test/quality/test-db; we use bash -c for the pipe.
func updateQualityGateDBTask() Task {
	return Task{
		Name:        "update-quality-gate-db",
		Description: "update pinned version of quality gate database",
		Run: func() {
			Run(`bash -c 'go run cmd/grype/main.go db list -o json | jq -r ` +
				`"\"https://grype.anchore.io/databases/v6/\" + .[0].path" > test/quality/test-db'`)
		},
	}
}

func showTestImageCacheTask() Task {
	return Task{
		Name: "show-test-image-cache",
		Run: func() {
			fmt.Println("\nDocker daemon cache:")
			Run(`bash -c "docker images --format '{{.ID}} {{.Repository}}:{{.Tag}}' | grep stereoscope-fixture- | sort"`)
			fmt.Println("\nTar cache:")
			Run(`bash -c "find . -type f -wholename '**/testdata/snapshot/*' | sort"`)
		},
	}
}

func cleanCacheTask() Task {
	return Task{
		Name:        "clean-cache",
		Description: "remove all docker cache and local image tar cache",
		RunsOn:      lang.List("clean"),
		Run: func() {
			Run(`bash -c "find . -type f -wholename '**/testdata/cache/stereoscope-fixture-*.tar' -delete"`)
			Run(`bash -c "docker images --format '{{.ID}} {{.Repository}}' | grep stereoscope-fixture- | awk '{print \$1}' | uniq | xargs -r docker rmi --force"`)
		},
	}
}

// requireCleanWorktree panics with msg if `git status --porcelain` is non-empty.
func requireCleanWorktree(msg string) {
	if !worktreeClean() {
		lang.Throw(fmt.Errorf("%s", msg))
	}
}

func worktreeClean() bool {
	out := Run(`git status --porcelain`, run.Quiet())
	return strings.TrimSpace(out) == ""
}

// regexpMatchSemverTag matches "vMAJOR.MINOR.PATCH" with no pre-release or build
// metadata. Pseudo-versions (v0.0.0-YYYYMMDDHHMMSS-shortsha) fail this check.
func regexpMatchSemverTag(s string) bool {
	if !strings.HasPrefix(s, "v") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
