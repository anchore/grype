package name

import (
	grypePkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Resolver interface {
	Normalize(string) string
	Names(p grypePkg.Package) []string
}

func FromType(t syftPkg.Type) Resolver {
	switch t {
	case syftPkg.PythonPkg:
		return &PythonResolver{}
	case syftPkg.JavaPkg:
		return &JavaResolver{}
	}

	return nil
}

func PackageNames(p grypePkg.Package) []string {
	names := []string{p.Name}
	r := FromType(p.Type)
	if r == nil {
		return names
	}

	parts := r.Names(p)
	if len(parts) > 0 {
		names = parts
	}
	return names
}

func Normalize(name string, pkgType syftPkg.Type) string {
	r := FromType(pkgType)
	if r != nil {
		return r.Normalize(name)
	}
	return name
}
