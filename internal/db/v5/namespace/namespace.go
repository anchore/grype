package namespace

import (
	"github.com/anchore/grype/internal/db/v5/pkg/resolver"
)

type Namespace interface {
	Provider() string
	Resolver() resolver.Resolver
	String() string
}
