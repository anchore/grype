package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/internal/redact"
)

type secret string

var _ interface {
	fmt.Stringer
	clio.PostLoader
} = (*secret)(nil)

// PostLoad needs to use a pointer receiver, even if it's not modifying the value
func (r *secret) PostLoad() error {
	redact.Add(string(*r))
	return nil
}

func (r secret) String() string {
	return string(r)
}
