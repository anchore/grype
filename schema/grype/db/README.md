# Grype v6 Database Schemas

This directory contains the schemas for the Grype v6 vulnerability database. These schemas are automatically generated from the Go code definitions and are used to track schema evolution over time.

## What Are These Schemas?

The Grype database has two types of schemas that are tracked:

### 1. SQL Schema (`sql/`)
The SQLite table definitions (CREATE TABLE and CREATE INDEX statements) generated from GORM models in `grype/db/v6/models.go`. This captures:
- Database tables and columns
- Foreign key relationships
- Indexes for query performance
- All structural aspects of the database

**Example tables:** `vulnerability_handles`, `packages`, `operating_systems`, `cpes`, `blobs`, etc.

### 2. Blob JSON Schema (`blob/json/`)
A unified JSON schema for all blob types stored in the `blobs` table. The blobs are JSON data referenced by various handle tables and include:
- `VulnerabilityBlob`: Core vulnerability advisory data
- `PackageBlob`: Package version ranges and fix information
- `KnownExploitedVulnerabilityBlob`: CISA KEV catalog data

## Schema Files

Each schema type has two files per version:

- **`schema-X.Y.Z.{sql|json}`**: The versioned schema file that should never be modified after creation
- **`schema-latest.{sql|json}`**: A copy of the most recent version to show diffs in PR reviews

The `-latest` files exist to make PR reviews easier. When you increment the schema version and regenerate, Git shows the new `schema-X.Y.Z` file as entirely new (just additions), which makes it hard to see what actually changed. The `-latest` file, however, is already tracked by Git, so it shows as a **diff** - making it easy to review exactly what changed in the schema.

## How to Regenerate Schemas

When you make changes to:
- GORM models in `grype/db/v6/models.go`
- Blob types in `grype/db/v6/blobs.go`

You need to regenerate the schemas:

```bash
task generate-db-schema
```

This will:
1. Create an in-memory SQLite database with all GORM models
2. Extract the SQL schema from the database
3. Generate a unified JSON schema for all blob types
4. Write the schemas to versioned files

## What to Do When Schema Changes

### If You're Adding Compatible Changes (Addition)
Examples: Adding a new optional field to a blob, adding a new index

1. Increment `Addition` in `grype/db/v6/db.go`:
   ```go
   Addition = 2  // was 1
   ```

2. Regenerate schemas:
   ```bash
   task generate-db-schema
   ```

3. Commit the new schema files along with your code changes

### If You're Making Potentially Breaking Changes (Revision)
Examples: Changing field types, removing optional fields, altering table structure

1. Increment `Revision` in `grype/db/v6/db.go` and reset `Addition`:
   ```go
   Revision = 2  // was 1
   Addition = 0  // reset
   ```

2. Regenerate and commit as above

### If You're Making Definitely Breaking Changes (Model)

Please meet with the team about this - it requires careful planning and
should be rare.

## Versioning Rules (SchemaVer)

This project uses [SchemaVer](https://docs.snowplowanalytics.com/docs/pipeline-components-and-applications/iglu/common-architecture/schemaver/) for schema versioning: `MODEL.REVISION.ADDITION`

- **MODEL**: Increment for breaking changes that prevent interaction with ALL historical data
- **REVISION**: Increment for changes that may prevent interaction with SOME historical data
- **ADDITION**: Increment for changes that are compatible with ALL historical data

**Important:** Never delete or modify existing versioned schema files! Only add new versions.

## CI Drift Detection

The static analysis CI check runs:

```bash
task check-db-schema-drift
```

This:
1. Checks that working directory is clean
2. Runs `task generate-db-schema`
3. Checks if any schema files changed

If schemas changed but weren't committed, the check fails. This ensures:
- Schema changes are always tracked
- Version numbers are incremented appropriately
- Code changes and schema changes stay in sync

This catches cases where you modified models or blob types but forgot to regenerate and commit the schemas.

## Common Errors

### "Cowardly refusing to overwrite existing schema"

This means:
- The schema has changed (code differs from committed schema)
- But the version number hasn't been incremented

**Solution:** Increment the appropriate version constant in `grype/db/v6/db.go`

### "Database blob schemas have uncommitted changes"

This means:
- You made schema changes
- Regenerated the schemas
- But haven't committed the new schema files

**Solution:** Add and commit the schema files in `schema/grype/db/`

## More Information

- **Generator Code**: `grype/db/v6/schema/main.go` - The Go program that generates these schemas
- **Version Constants**: `grype/db/v6/db.go` - Where `ModelVersion`, `Revision`, and `Addition` are defined
- **GORM Models**: `grype/db/v6/models.go` - The source for SQL schema generation
- **Blob Types**: `grype/db/v6/blobs.go` - The source for blob JSON schema generation
