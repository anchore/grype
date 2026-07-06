package dbsearch

const (
	// MatchesSchemaVersion is the schema version for the `db search` command
	MatchesSchemaVersion = "1.1.7"

	// MatchesSchemaVersion Changelog:
	// 1.0.0 - Initial schema 🎉
	// 1.0.1 - Add KEV and EPSS data to vulnerability matches
	// 1.0.2 - Add v5 namespace emulation for affected packages
	// 1.0.3 - Add severity string field to vulnerability object
	// 1.1.0 - Add fix available date information to vulnerability range object. This removes existing unused git-commit and date fields from the schema, but is a non-breaking change.
	// 1.1.1 - Add unaffected package and unaffected cpe to output
	// 1.1.2 - Add CWE IDs to vulnerability output
	// 1.1.3 - Add ID field to Reference (for advisory IDs like RHSA-2023:5455)
	// 1.1.4 - Add rpm_arch field to PackageQualifiers (source/binary tagging for the CSAF VEX transformer)
	// 1.1.5 - Add rootio field to PackageQualifiers (for Root IO NAK-pattern matching via the OSV rootio strategy)
	// 1.1.6 - Rename rpm_arch field on PackageQualifiers to architecture (semantics unchanged; rpm-specific prefix dropped)
	// 1.1.7 - Add go_imports field to PackageQualifiers (per-symbol reachability from govulndb ecosystem_specific.imports, used for Go binary symbol matching via the gosymbols qualifier).

	// VulnerabilitiesSchemaVersion is the schema version for the `db search vuln` command
	VulnerabilitiesSchemaVersion = "1.0.6"

	// VulnerabilitiesSchemaVersion
	// 1.0.0 - Initial schema 🎉
	// 1.0.1 - Add KEV and EPSS data to vulnerability
	// 1.0.3 - Add severity string field to vulnerability object
	// 1.0.4 - Add CWE IDs to vulnerability output
	// 1.0.5 - Add ID field to Reference (for advisory IDs like RHSA-2023:5455)
	// 1.0.6 - Add modifications and review_status fields to the vulnerability object
)
