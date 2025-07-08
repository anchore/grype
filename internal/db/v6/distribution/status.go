package distribution

type Status string

const LifecycleStatus = StatusActive

const (
	// StatusActive indicates the database is actively being maintained and distributed
	StatusActive Status = "active"

	// StatusDeprecated indicates the database is still being distributed but is approaching end of life. Upgrade grype to avoid future disruptions.
	StatusDeprecated Status = "deprecated"

	// StatusEndOfLife indicates the database is no longer being distributed. Users must build their own databases or upgrade grype.
	StatusEndOfLife Status = "eol"
)
