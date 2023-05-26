package namespace

import (
	"github.com/nextlinux/griffon/griffon/db/v4/pkg/resolver"
)

type Namespace interface {
	Provider() string
	Resolver() resolver.Resolver
	String() string
}
