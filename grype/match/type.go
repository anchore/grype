package match

const (
	ExactDirectMatch   Type = "Exact-Direct Match"
	ExactIndirectMatch Type = "Exact-Indirect Match"
	FuzzyMatch         Type = "Fuzzy Match"
)

type Type string
