package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/grype/internal/dbtest"
)

// regenerateCmd handles the 'regenerate' subcommand
func regenerateCmd(args []string) {
	var (
		vunnelData  string
		fixtureDir  string
		searchRoots stringSlice
		force       bool
		dryRun      bool
	)

	fs := flag.NewFlagSet("regenerate", flag.ExitOnError)
	fs.StringVar(&vunnelData, "vunnel-data", "", "path to vunnel data directory (required)")
	fs.StringVar(&fixtureDir, "fixture", "", "path to a specific fixture to regenerate (optional)")
	fs.Var(&searchRoots, "search-root", "root directory to search for fixtures (can be specified multiple times)")
	fs.BoolVar(&force, "force", false, "regenerate even if fixture has been modified")
	fs.BoolVar(&dryRun, "dry-run", false, "show what would be regenerated without making changes")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "regenerate - Regenerate fixtures from their db.yaml configs\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  manager regenerate --vunnel-data PATH [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Dry run to see what would be regenerated\n")
		fmt.Fprintf(os.Stderr, "  manager regenerate --vunnel-data ~/vunnel/data --dry-run\n\n")
		fmt.Fprintf(os.Stderr, "  # Regenerate all fixtures\n")
		fmt.Fprintf(os.Stderr, "  manager regenerate --vunnel-data ~/vunnel/data\n\n")
		fmt.Fprintf(os.Stderr, "  # Regenerate a specific fixture\n")
		fmt.Fprintf(os.Stderr, "  manager regenerate --vunnel-data ~/vunnel/data --fixture internal/dbtest/testdata/shared/my-fixture\n\n")
		fmt.Fprintf(os.Stderr, "  # Force regeneration of modified fixtures\n")
		fmt.Fprintf(os.Stderr, "  manager regenerate --vunnel-data ~/vunnel/data --force\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if vunnelData == "" {
		fmt.Fprintln(os.Stderr, "error: --vunnel-data is required")
		fs.Usage()
		os.Exit(1)
	}

	// verify vunnel data directory exists
	if _, err := os.Stat(vunnelData); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: vunnel data directory does not exist: %s\n", vunnelData)
		os.Exit(1)
	}

	opts := dbtest.RegenerateOptions{
		VunnelRoot: vunnelData,
		Force:      force,
		DryRun:     dryRun,
	}

	if fixtureDir != "" {
		// regenerate single fixture
		regenerateSingle(fixtureDir, opts)
	} else {
		// regenerate all fixtures
		roots := searchRoots
		if len(roots) == 0 {
			roots = defaultSearchRoots
		}
		regenerateAll(roots, opts)
	}
}

func regenerateSingle(fixtureDir string, opts dbtest.RegenerateOptions) {
	result, err := dbtest.RegenerateFixture(fixtureDir, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	displayPath := result.FixtureDir
	if rel, err := filepath.Rel(".", result.FixtureDir); err == nil {
		displayPath = rel
	}

	status := formatResult(result, opts.DryRun)
	switch {
	case result.Error != nil:
		status = red(status)
	case result.Skipped:
		status = yellow(status)
	}
	fmt.Printf("%s  %s\n", displayPath, status)

	if result.Error != nil {
		os.Exit(1)
	}
}

func regenerateAll(searchRoots []string, opts dbtest.RegenerateOptions) {
	results, err := dbtest.RegenerateAll(searchRoots, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Println("No fixtures found.")
		return
	}

	// first pass: collect display paths and find max length
	type displayResult struct {
		path   string
		result *dbtest.RegenerateResult
	}
	var displayResults []displayResult
	maxLen := 0

	for i := range results {
		displayPath := results[i].FixtureDir
		if rel, err := filepath.Rel(".", results[i].FixtureDir); err == nil {
			displayPath = rel
		}
		if len(displayPath) > maxLen {
			maxLen = len(displayPath)
		}
		displayResults = append(displayResults, displayResult{path: displayPath, result: &results[i]})
	}

	// second pass: print with alignment
	var errorCount int
	for _, dr := range displayResults {
		status := formatResult(dr.result, opts.DryRun)
		if dr.result.Error != nil {
			status = red(status)
			errorCount++
		} else if dr.result.Skipped {
			status = yellow(status)
		}
		fmt.Printf("%-*s  %s\n", maxLen, dr.path, status)
	}

	if errorCount > 0 {
		os.Exit(1)
	}
}

func formatResult(result *dbtest.RegenerateResult, dryRun bool) string {
	if result.Error != nil {
		return fmt.Sprintf("ERROR (%v)", result.Error)
	}
	if result.Skipped {
		return fmt.Sprintf("skipped (%s)", result.SkipReason)
	}
	if dryRun {
		return fmt.Sprintf("would regenerate (status: %s)", result.Status)
	}
	return green("regenerated")
}
