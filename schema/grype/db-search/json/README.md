# `db-search` JSON Schema

This is the JSON schema for output from the `grype db search` command. The required inputs for defining the JSON schema are as follows:

- the value of `cmd/grype/cli/commands/internal/dbsearch.MatchesSchemaVersion` that governs the schema version
- the `Matches` type definition within `github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch/matches.go` that governs the overall document shape

## Versioning

Versioning the JSON schema must be done manually by changing the `MatchesSchemaVersion` constant within `cmd/grype/cli/commands/internal/dbsearch/versions.go`.

This schema is being versioned based off of the "SchemaVer" guidelines, which slightly diverges from Semantic Versioning to tailor for the purposes of data models.

Given a version number format `MODEL.REVISION.ADDITION`:

- `MODEL`: increment when you make a breaking schema change which will prevent interaction with any historical data
- `REVISION`: increment when you make a schema change which may prevent interaction with some historical data
- `ADDITION`: increment when you make a schema change that is compatible with all historical data

## Generating a New Schema

Create the new schema by running `make generate-json-schema` from the root of the repo:

- If there is **not** an existing schema for the given version, then the new schema file will be written to `schema/grype/db-search/json/schema-$VERSION.json`
- If there is an existing schema for the given version and the new schema matches the existing schema, no action is taken
- If there is an existing schema for the given version and the new schema **does not** match the existing schema, an error is shown indicating to increment the version appropriately (see the "Versioning" section)

***Note: never delete a JSON schema and never change an existing JSON schema once it has been published in a release!*** Only add new schemas with a newly incremented version.
