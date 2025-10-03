package dbsearch

const (
	// MatchesSchemaVersion is the schema version for the `db search` command
	MatchesSchemaVersion = "1.1.3"

	// MatchesSchemaVersion Changelog:
	// 1.0.0 - Initial schema 🎉
	// 1.0.1 - Add KEV and EPSS data to vulnerability matches
	// 1.0.2 - Add v5 namespace emulation for affected packages
	// 1.0.3 - Add severity string field to vulnerability object
	// 1.1.0 - Add fix available date information to vulnerability range object. This removes existing unused git-commit and date fields from the schema, but is a non-breaking change.
	// 1.1.1 - Add unaffected package and unaffected cpe to output
	// 1.1.2 - Add CWE IDs to vulnerability output
	// 1.1.3 - Add ID field to Reference (for advisory IDs like RHSA-2023:5455)

	// VulnerabilitiesSchemaVersion is the schema version for the `db search vuln` command
	VulnerabilitiesSchemaVersion = "1.0.5"

	// VulnerabilitiesSchemaVersion
	// 1.0.0 - Initial schema 🎉
	// 1.0.1 - Add KEV and EPSS data to vulnerability
	// 1.0.3 - Add severity string field to vulnerability object
	// 1.0.4 - Add CWE IDs to vulnerability output
	// 1.0.5 - Add ID field to Reference (for advisory IDs like RHSA-2023:5455)
)
