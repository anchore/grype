# dbtest - Database Testing Utilities

This package provides utilities for building and testing grype vulnerability databases from fixture data.

## Quick Start

### Using Fixtures in Tests

```go
func TestVulnerabilityMatching(t *testing.T) {
    // use a fixture from your package's testdata directory
    dbtest.DBs(t, "my-fixture").Run(func(t *testing.T, db *dbtest.DB) {
        // db implements vulnerability.Provider
        vulns, err := db.FindVulnerabilities(...)
    })
}

func TestWithSharedFixture(t *testing.T) {
    // use a fixture from internal/dbtest/testdata/shared/
    dbtest.SharedDBs(t, "all").Run(func(t *testing.T, db *dbtest.DB) {
        matches := db.MustMatch(t, matcher, pkg)
    })
}
```

### Filtering Fixtures at Test Time

```go
// only include specific CVEs from a larger fixture
dbtest.SharedDBs(t, "all").
    SelectOnly("CVE-2024-1234", "CVE-2024-5678").
    Run(func(t *testing.T, db *dbtest.DB) {
        // db only contains the selected CVEs
    })
```

## Motivation

Testing grype's vulnerability matching requires realistic database fixtures. However, real vunnel caches can contain millions of records, making them impractical for test fixtures. This package solves several problems:

1. **Focused fixtures**: Extract only the specific CVEs or namespaces needed for a test scenario
2. **Deterministic tests**: Create reproducible fixtures from real vunnel data
3. **Easy maintenance**: Append new records to existing fixtures as test cases evolve
4. **Cross-package sharing**: Share fixtures between test packages via `SharedDBs()`
5. **Fixture provenance**: Track how fixtures were created and regenerate them when needed

## Go API

### Building Test Databases

The `Builder` type provides a fluent API for building test databases from fixtures:

```go
// DBs looks for testdata/<name> relative to the calling test file
func DBs(t *testing.T, fixtureName string) *Builder

// SharedDBs looks for fixtures in internal/dbtest/testdata/shared/<name>
func SharedDBs(t *testing.T, fixtureName string) *Builder

// SelectOnly filters which records are included (patterns combined with OR)
func (b *Builder) SelectOnly(patterns ...string) *Builder

// Run executes a test function for each schema version
func (b *Builder) Run(fn func(t *testing.T, db *DB))

// Build returns databases without running them through t.Run
func (b *Builder) Build(schemas ...int) []*DB
```

### The DB Type

`DB` wraps a `vulnerability.Provider` with test metadata:

```go
type DB struct {
    Name          string  // e.g., "v6"
    SchemaVersion int
    Path          string
}

// implements vulnerability.Provider
func (db *DB) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error)
func (db *DB) VulnerabilityMetadata(ref vulnerability.Reference) (*vulnerability.Metadata, error)
func (db *DB) PackageSearchNames(p grypePkg.Package) []string

// convenience method for matcher testing
func (db *DB) MustMatch(t *testing.T, matcher Matcher, p grypePkg.Package) []match.Match
```

### Extracting Fixtures from Vunnel Cache

Use `FixtureExtractor` to create fixtures from a vunnel data directory:

```go
extractor := dbtest.NewFixtureExtractor("/path/to/vunnel/data")

// extract to new fixture
err := extractor.
    From("debian").
    Select("CVE-2024-1234", "debian:10").
    WriteTo("internal/dbtest/testdata/shared/my-fixture")

// append to existing fixture
err := extractor.
    From("rhel").
    Select("RHSA-2024:").
    AppendTo("internal/dbtest/testdata/shared/my-fixture")

// multi-provider extraction
err := extractor.
    FromMultiple().
    Provider("debian", "CVE-2024-1234").
    Provider("nvd", "CVE-2024-1234").
    WriteTo("internal/dbtest/testdata/shared/multi-provider")
```

## CLI Tool

The manager CLI provides commands for creating and maintaining fixtures.

### Extract Command

Create fixtures from vunnel SQLite caches:

```bash
# extract specific CVEs
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider debian \
    --select "CVE-2024-1234" \
    --output internal/dbtest/testdata/shared/my-fixture

# extract by namespace (all CVEs in debian:11)
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider debian \
    --select "debian:11" \
    --output internal/dbtest/testdata/shared/debian11-vulns

# extract with multiple patterns (OR logic)
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider debian \
    --select "CVE-2024-1234" --select "CVE-2024-5678" \
    --output internal/dbtest/testdata/shared/specific-cves

# append to existing fixture
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider rhel \
    --select "RHSA-2024:" \
    --append internal/dbtest/testdata/shared/my-fixture

# extract from multiple providers
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider debian --provider nvd \
    --select "CVE-2024-1234" \
    --output internal/dbtest/testdata/shared/multi-provider
```

| Flag | Description |
|------|-------------|
| `--vunnel-data` | Path to vunnel data directory (required) |
| `--provider` | Provider name to extract from (repeatable) |
| `--select` | Pattern for record selection (repeatable) |
| `--output` | Path for new fixture directory |
| `--append` | Path to existing fixture to append to |

### Status Command

Check the status of all fixtures:

```bash
# show status of all fixtures
go run ./internal/dbtest/cmd/manager status

# show status of a specific fixture
go run ./internal/dbtest/cmd/manager status --fixture internal/dbtest/testdata/shared/my-fixture
```

Example output:

```
internal/dbtest/testdata/shared/all             OK (automatic, synced)
grype/matcher/dpkg/testdata/eol-debian8         OK (automatic, synced)
internal/dbtest/testdata/shared/manual-vuln     OK (manual)
internal/dbtest/testdata/shared/modified-one    CONTENT DRIFT (lock: a1b2c3d4, actual: e5f6g7h8)
```

### Regenerate Command

Regenerate fixtures from their `db.yaml` configs:

```bash
# dry run to see what would be regenerated
go run ./internal/dbtest/cmd/manager regenerate --vunnel-data ~/vunnel/data --dry-run

# regenerate all fixtures
go run ./internal/dbtest/cmd/manager regenerate --vunnel-data ~/vunnel/data

# regenerate a specific fixture
go run ./internal/dbtest/cmd/manager regenerate --vunnel-data ~/vunnel/data --fixture path/to/fixture

# force regeneration even if fixture has been modified
go run ./internal/dbtest/cmd/manager regenerate --vunnel-data ~/vunnel/data --force
```

| Flag | Description |
|------|-------------|
| `--vunnel-data` | Path to vunnel data directory (required) |
| `--fixture` | Path to a specific fixture to regenerate |
| `--search-root` | Root directory to search for fixtures (repeatable) |
| `--force` | Regenerate even if fixture has been modified |
| `--dry-run` | Show what would be regenerated without making changes |

## Pattern Matching

Patterns use SQL `LIKE` matching with automatic wildcards. All patterns are wrapped with `%` for partial matching.

| Pattern | Matches | Description |
|---------|---------|-------------|
| `CVE-2024-1234` | `debian:10/CVE-2024-1234`, `ubuntu:20.04/CVE-2024-1234` | Matches CVE in any namespace |
| `debian:10` | `debian:10/CVE-2024-1234`, `debian:10/CVE-2024-5678` | Matches all CVEs in namespace |
| `debian` | `debian:10/...`, `debian:11/...` | Matches all debian namespaces |
| `RHSA-2024:` | `rhel:8/RHSA-2024:0001`, `rhel:9/RHSA-2024:0002` | Matches all 2024 RHSAs |
| `debian:11/CVE-2024-1234` | `debian:11/CVE-2024-1234` | Exact match |

Multiple `--select` patterns are combined with OR logic.

## Fixture Structure

Extracted fixtures follow the vunnel workspace format:

```
fixture/
├── db.yaml               # extraction config (auto-generate flag, patterns)
├── db-lock.json          # state tracking (content hash, timestamps)
├── provider-name/
│   ├── metadata.json     # provider state (store: "flat-file")
│   └── results/
│       ├── debian@11_CVE-2024-1234.json
│       ├── debian@11_CVE-2024-5678.json
│       └── listing.xxh64
└── another-provider/
    ├── metadata.json
    └── results/
        └── ...
```

Note: `:` in identifiers is replaced with `@` and `/` with `_` in filenames.

## Tracking and Regenerating Fixtures

When you extract a fixture, the manager creates two metadata files:

- `db.yaml` - **Intent**: What extractions to perform (human-editable)
- `db-lock.json` - **State**: What was done (machine-generated)

### db.yaml

```yaml
auto-generate: true
extractions:
  debian:
    - CVE-2024-1234
    - debian:10
  nvd:
    - CVE-2024-1234
```

| Field | Description |
|-------|-------------|
| `auto-generate` | If `true`, fixture can be regenerated from vunnel cache |
| `extractions` | Map of provider name to list of patterns |

### db-lock.json

```json
{
  "content_hash": "a1b2c3d4e5f6g7h8",
  "created_at": "2024-01-15T12:00:00Z",
  "regenerated_at": "2024-03-12T10:30:00Z",
  "providers": {
    "debian": {
      "vunnel_version": "vunnel@0.55.2",
      "timestamp": "2024-03-11T16:25:19Z"
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `content_hash` | xxh64 hash of fixture content (excludes db.yaml and db-lock.json) |
| `created_at` | When fixture was first created |
| `regenerated_at` | When last regenerated (omitted if never regenerated) |
| `providers.<name>.vunnel_version` | Vunnel version from provider's metadata |
| `providers.<name>.timestamp` | Provider's data timestamp |

### Fixture Status

| Status | Description |
|--------|-------------|
| `OK` (automatic) | `auto-generate: true` and content hash matches lock |
| `OK` (manual) | `auto-generate: false` - manually created, never auto-regenerated |
| `content_drift` | `auto-generate: true` but files have changed since last generation |
| `config_ahead` | `auto-generate: true` but config has providers not in lock |
| `no_lock` | `auto-generate: true` but db-lock.json is missing |
| `no_config` | No db.yaml file present |

## Workflows

### Creating a New Fixture

```bash
# 1. extract (db.yaml and db-lock.json created automatically)
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider debian --select "CVE-2024-1234" \
    --output internal/dbtest/testdata/shared/my-fixture

# 2. optionally append more providers/CVEs
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider nvd --select "CVE-2024-1234" \
    --append internal/dbtest/testdata/shared/my-fixture

# 3. commit
git add internal/dbtest/testdata/shared/my-fixture/
git commit -m "add my-fixture test fixture"
```

### Creating a Manual Fixture

Manual fixtures are never automatically regenerated, useful when you need custom modifications:

```bash
# 1. extract base
go run ./internal/dbtest/cmd/manager extract \
    --vunnel-data ~/vunnel/data \
    --provider debian --select "CVE-2024-1234" \
    --output internal/dbtest/testdata/shared/manual-fixture

# 2. manually modify files as needed
vim internal/dbtest/testdata/shared/manual-fixture/debian/results/...

# 3. edit db.yaml to set auto-generate: false
# (prevents automatic regeneration)

# 4. commit
git add internal/dbtest/testdata/shared/manual-fixture/
git commit -m "add manual-fixture with custom modifications"
```

### Regenerating Fixtures

When vunnel data is updated, regenerate fixtures to get fresh vulnerability data:

```bash
# 1. check current status
go run ./internal/dbtest/cmd/manager status

# 2. dry run to see what would happen
go run ./internal/dbtest/cmd/manager regenerate --vunnel-data ~/vunnel/data --dry-run

# 3. regenerate (skips manual and modified fixtures)
go run ./internal/dbtest/cmd/manager regenerate --vunnel-data ~/vunnel/data

# 4. run tests to verify
go test ./...
```
