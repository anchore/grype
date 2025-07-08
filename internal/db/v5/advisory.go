package v5

// Advisory represents published statements regarding a vulnerability (and potentially about its resolution).
type Advisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}
