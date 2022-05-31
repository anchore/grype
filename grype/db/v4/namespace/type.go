package namespace

// Type represents a namespace type
type Type string

const (
	// represents the set of supported namespace types

	CPE      Type = "cpe"
	Language Type = "language"
	Distro   Type = "distro"
)

// All contains all namespace types
var All = []Type{
	CPE,
	Language,
	Distro,
}

// String returns the string representation of the given namespace type.
func (t Type) String() string {
	return string(t)
}
