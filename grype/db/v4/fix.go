package v4

type FixState string

const (
	UnknownFixState FixState = "unknown"
	FixedState      FixState = "fixed"
	NotFixedState   FixState = "not-fixed"
	WontFixState    FixState = "wont-fix"
)

// Fix represents all information about known fixes for a stated vulnerability.
type Fix struct {
	Versions []string // The version(s) which this particular vulnerability was fixed in
	State    FixState
}
