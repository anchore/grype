package v4

// Advisory represents published statements regarding a vulnerability (and potentially about it's resolution).
type Advisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}
