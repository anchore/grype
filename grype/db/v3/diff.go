package v3

type DiffReason = string

const (
	Diff_Added   DiffReason = "added"
	Diff_Changed DiffReason = "changed"
	Diff_Removed DiffReason = "removed"
)

type Diff struct {
	Reason    DiffReason `json:"reason"`
	ID        string     `json:"id"`
	Namespace string     `json:"namespace"`
}
