package version

// NewVersion creates a new Version instance with the provided raw version string and format.
//
// Deprecated: NewVersion is deprecated, use New instead.
func NewVersion(raw string, format Format) *Version {
	return New(raw, format)
}
