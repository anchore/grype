package v4

type DiffReason = string

const (
	DiffAdded   DiffReason = "added"
	DiffChanged DiffReason = "changed"
	DiffRemoved DiffReason = "removed"
)

type Diff struct {
	Reason    DiffReason `json:"reason"`
	ID        string     `json:"id"`
	Namespace string     `json:"namespace"`
}
