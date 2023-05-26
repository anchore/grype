package resolver

import (
	griffonPkg "github.com/nextlinux/griffon/griffon/pkg"
)

type Resolver interface {
	Normalize(string) string
	Resolve(p griffonPkg.Package) []string
}
