package main

import (
	"fmt"
	"os"
	"strings"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/log"
	"github.com/anchore/go-make/run"
)

// Local-iteration defaults: small enough to finish in single-digit minutes
// on a laptop and large enough to exercise both OS and language matchers.
const (
	defaultDBBuilderProviders   = "wolfi"
	defaultDBBuilderRoot        = "./data"
	defaultDBBuilderDir         = "./build"
	defaultDBBuilderCacheDir    = "./.cache/vunnel"
	defaultDBBuilderVunnelImage = "ghcr.io/anchore/vunnel:latest"
	// ghcr.io path retains "grype-db" because that's the existing ORAS
	// artifact namespace populated by the daily-data-sync pipeline; the
	// string has nothing to do with the grype-db binary.
	defaultDBBuilderCacheImage = "ghcr.io/anchore/grype-db/data"
	defaultDBBuilderCacheTag   = "latest"
)

// dbBuilderTasks wraps a local end-to-end workflow that builds a vulnerability
// database from a fresh grype checkout, using only `grype db-builder` (no
// grype-db binary required). The intent is twofold: a fast inner-loop for
// developers iterating on the builder code, and a reproducible recipe a
// reviewer can run to confirm grype can produce a real DB on its own.
//
// The pipeline mirrors the production data-sync flow: restore the previous
// day's vunnel workspace from ghcr.io (cache-restore), refresh it with a new
// vunnel run (pull), then build and package. The cache restore is required
// for any non-trivial provider — running vunnel from scratch against NVD,
// for example, takes hours.
//
// Environment knobs:
//
//	DB_BUILDER_PROVIDERS    csv of provider names to run (default: wolfi)
//	DB_BUILDER_ROOT         vunnel workspace directory   (default: ./data)
//	DB_BUILDER_DIR          DB build directory           (default: ./build)
//	DB_BUILDER_CACHE_DIR    scratch dir for ORAS pulls   (default: ./.cache/vunnel)
//	DB_BUILDER_CACHE_IMAGE  ghcr.io image base path      (default: ghcr.io/anchore/grype-db/data)
//	DB_BUILDER_CACHE_TAG    image tag to pull            (default: latest)
//	DB_BUILDER_VUNNEL_IMAGE vunnel docker image          (default: ghcr.io/anchore/vunnel:latest)
func dbBuilderTasks() Task {
	return Task{
		Name:         "db-builder",
		Description:  "build a local vulnerability DB end-to-end using 'grype db-builder' (no grype-db dependency)",
		Dependencies: Deps("db-builder:pull", "db-builder:build", "db-builder:package"),
		Tasks: []Task{
			{
				Name:        "db-builder:bootstrap",
				Description: "pull the vunnel docker image so subsequent pulls don't block on network",
				Run: func() {
					Run(fmt.Sprintf("docker pull %s", dbBuilderVunnelImage()))
				},
			},
			{
				Name: "db-builder:cache-restore",
				Description: "for each provider in DB_BUILDER_PROVIDERS: ORAS pull the workspace tarball " +
					"from ghcr.io and extract into DB_BUILDER_ROOT",
				Run: func() {
					providers := dbBuilderProviderList()
					root := dbBuilderRoot()
					cacheDir := dbBuilderCacheDir()
					image := dbBuilderCacheImage()
					tag := dbBuilderCacheTag()

					if err := os.MkdirAll(cacheDir, 0o755); err != nil {
						log.Error(fmt.Errorf("create cache dir %s: %w", cacheDir, err))
						return
					}

					for _, p := range providers {
						providerCacheDir := fmt.Sprintf("%s/%s", cacheDir, p)
						tarball := fmt.Sprintf("%s/grype-db-cache.tar.gz", providerCacheDir)
						log.Info("restoring provider %q workspace from %s/%s:%s", p, image, p, tag)

						// oras pull writes files into pwd with the path they had when pushed:
						// .cache/vunnel/<provider>/grype-db-cache.tar.gz. Run from repo root.
						// NoFail so a missing tag for a new provider doesn't abort the whole batch.
						out := Run(fmt.Sprintf("oras pull %s/%s:%s", image, p, tag), run.NoFail())
						if !file.Exists(tarball) {
							log.Info("no cache available for %q (oras output: %s); skipping", p, strings.TrimSpace(out))
							continue
						}

						Run(fmt.Sprintf("go run ./cmd/grype db-builder cache restore --path %s --delete-existing -p %s",
							tarball, p),
							run.Env("GRYPE_DB_BUILDER_PROVIDER_ROOT", root),
						)
						_ = os.RemoveAll(providerCacheDir)
					}
				},
			},
			{
				Name:        "db-builder:cache-backup",
				Description: "snapshot the local DB_BUILDER_ROOT workspaces into per-provider tarballs under DB_BUILDER_CACHE_DIR (does not push to ghcr.io)",
				Run: func() {
					providers := dbBuilderProviderList()
					root := dbBuilderRoot()
					cacheDir := dbBuilderCacheDir()

					if err := os.MkdirAll(cacheDir, 0o755); err != nil {
						log.Error(fmt.Errorf("create cache dir %s: %w", cacheDir, err))
						return
					}
					for _, p := range providers {
						providerCacheDir := fmt.Sprintf("%s/%s", cacheDir, p)
						if err := os.MkdirAll(providerCacheDir, 0o755); err != nil {
							log.Error(fmt.Errorf("create %s: %w", providerCacheDir, err))
							continue
						}
						tarball := fmt.Sprintf("%s/grype-db-cache.tar.gz", providerCacheDir)
						Run(fmt.Sprintf("go run ./cmd/grype db-builder cache backup --path %s -p %s", tarball, p),
							run.Env("GRYPE_DB_BUILDER_PROVIDER_ROOT", root),
						)
					}
				},
			},
			{
				Name: "db-builder:pull",
				Description: "restore each provider's workspace from ghcr.io and refresh it with a vunnel run " +
					"(mirrors the production data-sync per-provider step)",
				Dependencies: Deps("db-builder:bootstrap", "db-builder:cache-restore"),
				Run: func() {
					providers := dbBuilderProvidersCSV()
					Run(fmt.Sprintf("go run ./cmd/grype db-builder pull -p %s", providers),
						dbBuilderEnv()...)
				},
			},
			{
				Name:        "db-builder:build",
				Description: "write a SQLite DB from existing workspace data in DB_BUILDER_ROOT",
				Run: func() {
					providers := dbBuilderProvidersCSV()
					Run(fmt.Sprintf("go run ./cmd/grype db-builder build -p %s", providers),
						dbBuilderEnv()...)
				},
			},
			{
				Name:        "db-builder:package",
				Description: "package the DB at DB_BUILDER_DIR into a distributable archive",
				Run: func() {
					Run("go run ./cmd/grype db-builder package", dbBuilderEnv()...)
				},
			},
			{
				Name:        "db-builder:clean",
				Description: "remove DB_BUILDER_ROOT, DB_BUILDER_DIR, and DB_BUILDER_CACHE_DIR",
				Run: func() {
					for _, dir := range []string{dbBuilderRoot(), dbBuilderDir(), dbBuilderCacheDir()} {
						if err := os.RemoveAll(dir); err != nil {
							log.Error(fmt.Errorf("remove %s: %w", dir, err))
						} else {
							log.Info("removed %s", dir)
						}
					}
				},
			},
		},
	}
}

// dbBuilderEnv returns run.Options that point the embedded `grype`
// subprocess at the user-selected workspace + build dirs. Using
// GRYPE_DB_BUILDER_* env vars (rather than CLI flags) keeps the Run()
// invocations short and matches how the grype-db-manager will eventually
// invoke grype.
func dbBuilderEnv() []run.Option {
	return []run.Option{
		run.Env("GRYPE_DB_BUILDER_PROVIDER_ROOT", dbBuilderRoot()),
		run.Env("GRYPE_DB_BUILDER_DIR", dbBuilderDir()),
	}
}

// dbBuilderProviderList returns the parsed list of providers from
// DB_BUILDER_PROVIDERS (or the default), used by per-provider loops.
func dbBuilderProviderList() []string {
	raw := os.Getenv("DB_BUILDER_PROVIDERS")
	if raw == "" {
		raw = defaultDBBuilderProviders
	}
	var parts []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

func dbBuilderProvidersCSV() string {
	raw := os.Getenv("DB_BUILDER_PROVIDERS")
	if raw == "" {
		raw = defaultDBBuilderProviders
	}
	// normalize: trim spaces, drop empties — the underlying PostLoad in grype
	// also flattens csv, but we sanitize here so '--help' echoes a clean list.
	var parts []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

func dbBuilderRoot() string {
	if v := os.Getenv("DB_BUILDER_ROOT"); v != "" {
		return v
	}
	return defaultDBBuilderRoot
}

func dbBuilderDir() string {
	if v := os.Getenv("DB_BUILDER_DIR"); v != "" {
		return v
	}
	return defaultDBBuilderDir
}

func dbBuilderVunnelImage() string {
	if v := os.Getenv("DB_BUILDER_VUNNEL_IMAGE"); v != "" {
		return v
	}
	return defaultDBBuilderVunnelImage
}

func dbBuilderCacheDir() string {
	if v := os.Getenv("DB_BUILDER_CACHE_DIR"); v != "" {
		return v
	}
	return defaultDBBuilderCacheDir
}

func dbBuilderCacheImage() string {
	if v := os.Getenv("DB_BUILDER_CACHE_IMAGE"); v != "" {
		return v
	}
	return defaultDBBuilderCacheImage
}

func dbBuilderCacheTag() string {
	if v := os.Getenv("DB_BUILDER_CACHE_TAG"); v != "" {
		return v
	}
	return defaultDBBuilderCacheTag
}
