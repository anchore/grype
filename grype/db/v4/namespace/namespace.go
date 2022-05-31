package namespace

import (
	"github.com/anchore/grype/grype/db/v4/pkg/resolver"
)

const Separator = ":"

type Namespace interface {
	Provider() string
	Type() Type
	Resolver() resolver.Resolver
}
