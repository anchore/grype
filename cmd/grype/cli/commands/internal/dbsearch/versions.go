package dbsearch

const (
	// MatchesSchemaVersion is the schema version for the `db search ` command
	MatchesSchemaVersion = "1.0.2"

	// MatchesSchemaVersion Changelog:
	// 1.0.0 - Initial schema 🎉
	// 1.0.1 - Add KEV and EPSS data to vulnerability matches
	// 1.0.2 - Add v5 namespace emulation for affected packages

	// VulnerabilitiesSchemaVersion is the schema version for the `db search vuln` command
	VulnerabilitiesSchemaVersion = "1.0.1"

	// VulnerabilitiesSchemaVersion
	// 1.0.0 - Initial schema 🎉
	// 1.0.1 - Add KEV and EPSS data to vulnerability
)
