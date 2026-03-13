// manager is a CLI tool for creating and maintaining test fixtures from vunnel SQLite caches.
//
// Subcommands:
//
//	extract - Extract records from vunnel caches to create test fixtures
//	status  - Show the status of all test fixtures
//	regenerate - Regenerate test fixtures from their db.yaml configs
//
// Usage:
//
//	# extract debian CVEs to new fixture
//	go run ./internal/dbtest/cmd/manager extract \
//	    --vunnel-data /path/to/vunnel/data \
//	    --provider debian \
//	    --select "CVE-2024-1234" \
//	    --output internal/dbtest/testdata/shared/new-fixture
//
//	# show status of all fixtures
//	go run ./internal/dbtest/cmd/manager status
//
//	# regenerate all fixtures
//	go run ./internal/dbtest/cmd/manager regenerate --vunnel-data /path/to/vunnel/data
package main

import (
	"fmt"
	"os"
	"strings"
)

var defaultSearchRoots = []string{
	"internal/dbtest/testdata",
	"grype",
}

func main() {
	if len(os.Args) < 2 {
		printMainUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "extract":
		extractCmd(os.Args[2:])
	case "status":
		statusCmd(os.Args[2:])
	case "regenerate":
		regenerateCmd(os.Args[2:])
	case "-h", "--help", "help":
		printMainUsage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n\n", os.Args[1])
		printMainUsage()
		os.Exit(1)
	}
}

func printMainUsage() {
	fmt.Fprintf(os.Stderr, `manager - Create and maintain test fixtures from vunnel SQLite caches

Usage:
  manager <command> [options]

Commands:
  extract     Extract records from vunnel caches to create fixtures
  status      Show status of all test fixtures
  regenerate  Regenerate fixtures from their db.yaml configs

Run 'manager <command> --help' for details on each command.
`)
}

// stringSlice implements flag.Value for collecting multiple string flags
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
