package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/grype/internal/dbtest"
)

// statusCmd handles the 'status' subcommand
func statusCmd(args []string) {
	var (
		fixtureDir  string
		searchRoots stringSlice
	)

	fs := flag.NewFlagSet("status", flag.ExitOnError)
	fs.StringVar(&fixtureDir, "fixture", "", "path to a specific fixture directory (optional)")
	fs.Var(&searchRoots, "search-root", "root directory to search for fixtures (can be specified multiple times)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "status - Show status of test fixtures\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  manager status [--fixture PATH] [--search-root PATH...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Show status of all fixtures\n")
		fmt.Fprintf(os.Stderr, "  manager status\n\n")
		fmt.Fprintf(os.Stderr, "  # Show status of a specific fixture\n")
		fmt.Fprintf(os.Stderr, "  manager status --fixture internal/dbtest/testdata/shared/my-fixture\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fixtureDir != "" {
		// show status of single fixture
		showFixtureStatus(fixtureDir)
	} else {
		// discover and show status of all fixtures
		roots := searchRoots
		if len(roots) == 0 {
			roots = defaultSearchRoots
		}
		showAllFixtureStatus(roots)
	}
}

func showFixtureStatus(fixtureDir string) {
	detail, err := dbtest.GetFixtureStatusDetail(fixtureDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s: %s\n", fixtureDir, formatStatusDetail(detail))
}

func showAllFixtureStatus(searchRoots []string) {
	fixtures, err := dbtest.DiscoverFixtures(searchRoots...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error discovering fixtures: %v\n", err)
		os.Exit(1)
	}

	if len(fixtures) == 0 {
		fmt.Println("No fixtures found.")
		return
	}

	// first pass: collect results and find max path length
	type result struct {
		path   string
		detail *dbtest.FixtureStatusDetail
		err    error
	}
	var results []result
	maxLen := 0

	for _, fixture := range fixtures {
		displayPath := fixture
		if rel, err := filepath.Rel(".", fixture); err == nil {
			displayPath = rel
		}
		if len(displayPath) > maxLen {
			maxLen = len(displayPath)
		}

		detail, err := dbtest.GetFixtureStatusDetail(fixture)
		results = append(results, result{path: displayPath, detail: detail, err: err})
	}

	// second pass: print with alignment
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("%-*s  %s\n", maxLen, r.path, red(fmt.Sprintf("ERROR (%v)", r.err)))
			continue
		}

		status := formatStatusDetail(r.detail)
		if r.detail.Status != dbtest.StatusOK && r.detail.Status != dbtest.StatusManual {
			status = yellow(status)
		}
		fmt.Printf("%-*s  %s\n", maxLen, r.path, status)
	}
}

func formatStatusDetail(detail *dbtest.FixtureStatusDetail) string {
	switch detail.Status {
	case dbtest.StatusOK:
		return green("OK") + " (automatic, synced)"
	case dbtest.StatusContentDrift:
		return fmt.Sprintf("CONTENT DRIFT (lock: %s, actual: %s)", truncateHash(detail.LockHash), truncateHash(detail.ContentHash))
	case dbtest.StatusConfigAhead:
		return fmt.Sprintf("CONFIG AHEAD (missing in lock: %v)", detail.MissingInLock)
	case dbtest.StatusNoLock:
		return "NO LOCK (db-lock.json missing)"
	case dbtest.StatusManual:
		return green("OK") + " (manual)"
	case dbtest.StatusNoConfig:
		return "no config"
	default:
		return string(detail.Status)
	}
}

func truncateHash(hash string) string {
	if len(hash) <= 8 {
		return hash
	}
	return hash[:8]
}
