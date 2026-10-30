# Configuration file JSON Schema

This is the JSON schema for the grype configuration file (`.grype.yaml`, `.grype/config.yaml`, `~/.grype.yaml`, `$XDG_CONFIG_HOME/grype/config.yaml`). The required inputs for defining the JSON schema are as follows:

- the value of `cmd/grype/cli/options.ConfigSchemaVersion` that governs the schema version
- the `options.Grype` type (from `options.DefaultGrype`) together with the `clio.Config` logging and development sections, which govern the overall document shape
- the field descriptions registered via `DescribeFields` and the CLI flag usage text, which become the schema descriptions (the same text shown by `grype config`)
- the constraints (allowed values, patterns) curated in `cmd/grype/cli/commands/internal/jsonschema/config_constraints.go`

The schema is strict: unknown keys are rejected (`additionalProperties: false`), so typos are reported by editors even though grype itself silently ignores unknown keys.

## Versioning

Versioning the JSON schema must be done manually by changing the `ConfigSchemaVersion` constant within `cmd/grype/cli/options/config_schema_version.go`.

This schema is being versioned based off of the "SchemaVer" guidelines, which slightly diverges from Semantic Versioning to tailor for the purposes of data models.

Given a version number format `MODEL.REVISION.ADDITION`:

- `MODEL`: increment when you make a breaking schema change which will prevent interaction with any historical data (e.g. removing or renaming a configuration key)
- `REVISION`: increment when you make a schema change which may prevent interaction with some historical data (e.g. narrowing the allowed values of a key)
- `ADDITION`: increment when you make a schema change that is compatible with all historical data (e.g. adding a configuration key or changing a description or default)

## Generating a New Schema

Create the new schema by running `make generate:json-schema` from the root of the repo:

- If there is **not** an existing schema for the given version, then the new schema file will be written to `schema/grype/config/json/schema-$VERSION.json`
- If there is an existing schema for the given version and the new schema matches the existing schema, no action is taken
- If there is an existing schema for the given version and the new schema **does not** match the existing schema, an error is shown indicating to increment the version appropriately (see the "Versioning" section)

The `TestConfigSchemaUpToDate` unit test fails when the committed schema no longer matches the configuration code, so any change to the configuration options requires regenerating the schema.

***Note: never delete a JSON schema and never change an existing JSON schema once it has been published in a release!*** Only add new schemas with a newly incremented version.

## Editor Integration

Editors using [yaml-language-server](https://github.com/redhat-developer/yaml-language-server) (e.g. VS Code with the Red Hat YAML extension, Neovim, JetBrains IDEs) provide completion, hover documentation and validation once the schema is associated with the configuration file.

Add a modeline as the first line of the configuration file:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/anchore/grype/main/schema/grype/config/json/schema-latest.json
```

Or associate the schema with configuration files in the VS Code settings:

```json
{
  "yaml.schemas": {
    "https://raw.githubusercontent.com/anchore/grype/main/schema/grype/config/json/schema-latest.json": [".grype.yaml", ".grype.yml", ".grype/config.yaml", ".grype/config.yml"]
  }
}
```

To match a specific grype release, replace `main` in the URL with the release tag (e.g. `v0.100.0`).

## Known Limitations

- Allowed values are listed in their canonical lower-case form, while grype accepts some of them case-insensitively (e.g. `fail-on-severity: High`).
- List values may also be given as a comma-separated string (e.g. `output: json,table`); in that form the individual items are not checked against the allowed values.
- The fields of `ignore` rules and `registry.auth` entries have no descriptions yet; they are documented in the description of their parent key.
