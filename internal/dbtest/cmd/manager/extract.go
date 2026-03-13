package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/anchore/grype/internal/dbtest"
)

// extractCmd handles the 'extract' subcommand
func extractCmd(args []string) {
	var (
		vunnelData string
		providers  stringSlice
		selects    stringSlice
		outputDir  string
		appendDir  string
	)

	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	fs.StringVar(&vunnelData, "vunnel-data", "", "path to vunnel data directory (required)")
	fs.Var(&providers, "provider", "provider name to extract from (can be specified multiple times)")
	fs.Var(&selects, "select", "pattern for record selection using SQL LIKE matching (can be specified multiple times)")
	fs.StringVar(&outputDir, "output", "", "path for new fixture directory (mutually exclusive with --append)")
	fs.StringVar(&appendDir, "append", "", "path for existing fixture directory to append to (mutually exclusive with --output)")

	fs.Usage = extractUsage(fs)

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	validateExtractFlags(fs, vunnelData, providers, selects, outputDir, appendDir)

	// determine target directory and operation mode
	targetDir, appendMode := determineTargetDir(outputDir, appendDir)

	performExtraction(vunnelData, providers, selects, targetDir, appendMode)
}

func extractUsage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "extract - Extract records from vunnel caches to create fixtures\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  manager extract --vunnel-data PATH --provider NAME --select PATTERN [--output DIR | --append DIR]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Extract specific CVEs from debian provider\n")
		fmt.Fprintf(os.Stderr, "  manager extract --vunnel-data ~/vunnel/data --provider debian --select CVE-2024-1234 --output ./fixtures/new\n\n")
		fmt.Fprintf(os.Stderr, "  # Extract by namespace\n")
		fmt.Fprintf(os.Stderr, "  manager extract --vunnel-data ~/vunnel/data --provider debian --select \"debian:10\" --output ./fixtures/debian10\n\n")
		fmt.Fprintf(os.Stderr, "  # Append to existing fixture\n")
		fmt.Fprintf(os.Stderr, "  manager extract --vunnel-data ~/vunnel/data --provider rhel --select \"RHSA-2024\" --append ./fixtures/existing\n\n")
		fmt.Fprintf(os.Stderr, "  # Extract from multiple providers\n")
		fmt.Fprintf(os.Stderr, "  manager extract --vunnel-data ~/vunnel/data --provider debian --provider nvd --select CVE-2024-1234 --output ./fixtures/multi\n")
	}
}

func validateExtractFlags(fs *flag.FlagSet, vunnelData string, providers, selects stringSlice, outputDir, appendDir string) {
	if vunnelData == "" {
		fmt.Fprintln(os.Stderr, "error: --vunnel-data is required")
		fs.Usage()
		os.Exit(1)
	}

	if len(providers) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one --provider is required")
		fs.Usage()
		os.Exit(1)
	}

	if len(selects) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one --select pattern is required")
		fs.Usage()
		os.Exit(1)
	}

	if outputDir == "" && appendDir == "" {
		fmt.Fprintln(os.Stderr, "error: either --output or --append is required")
		fs.Usage()
		os.Exit(1)
	}

	if outputDir != "" && appendDir != "" {
		fmt.Fprintln(os.Stderr, "error: --output and --append are mutually exclusive")
		fs.Usage()
		os.Exit(1)
	}

	if _, err := os.Stat(vunnelData); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: vunnel data directory does not exist: %s\n", vunnelData)
		os.Exit(1)
	}
}

func determineTargetDir(outputDir, appendDir string) (string, bool) {
	if appendDir != "" {
		return appendDir, true
	}
	return outputDir, false
}

func performExtraction(vunnelData string, providers, selects stringSlice, targetDir string, appendMode bool) {
	extractor := dbtest.NewFixtureExtractor(vunnelData)

	if len(providers) == 1 {
		extractSingleProvider(extractor, providers[0], selects, targetDir, appendMode)
	} else {
		extractMultipleProviders(extractor, providers, selects, targetDir, appendMode)
	}
}

func extractSingleProvider(extractor *dbtest.FixtureExtractor, provider string, selects stringSlice, targetDir string, appendMode bool) {
	builder := extractor.From(provider).Select(selects...)
	var err error
	if appendMode {
		err = builder.AppendTo(targetDir)
	} else {
		err = builder.WriteTo(targetDir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error extracting from provider %q: %v\n", provider, err)
		os.Exit(1)
	}
	fmt.Printf("Successfully extracted from %s to %s\n", provider, targetDir)
}

func extractMultipleProviders(extractor *dbtest.FixtureExtractor, providers, selects stringSlice, targetDir string, appendMode bool) {
	multiBuilder := extractor.FromMultiple()
	for _, p := range providers {
		multiBuilder = multiBuilder.Provider(p, selects...)
	}

	var err error
	if appendMode {
		err = multiBuilder.AppendTo(targetDir)
	} else {
		err = multiBuilder.WriteTo(targetDir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully extracted from %d providers to %s\n", len(providers), targetDir)
}
