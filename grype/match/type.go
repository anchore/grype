package match

const (
	ExactDirectMatch   Type = "exact-direct-match"
	ExactIndirectMatch Type = "exact-indirect-match"
	CPEMatch           Type = "cpe-match"
)

type Type string
