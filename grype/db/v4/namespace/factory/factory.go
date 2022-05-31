package factory

import (
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/db/v4/namespace"
	"github.com/anchore/grype/grype/db/v4/namespace/cpe"
	"github.com/anchore/grype/grype/db/v4/namespace/distro"
	"github.com/anchore/grype/grype/db/v4/namespace/language"
	"strings"
)

func FromString(namespaceStr string) (namespace.Namespace, error) {
	if namespaceStr == "" {
		return nil, errors.New("unable to create namespace from empty string")
	}

	components := strings.Split(namespaceStr, namespace.Separator)

	if len(components) < 1 {
		return nil, fmt.Errorf("unable to create namespace from %s: incorrect number of components", namespaceStr)
	}

	switch components[1] {
	case string(namespace.CPE):
		return cpe.FromString(namespaceStr)
	case string(namespace.Distro):
		return distro.FromString(namespaceStr)
	case string(namespace.Language):
		return language.FromString(namespaceStr)
	default:
		return nil, fmt.Errorf("unable to create namespace from %s: unknown type %s", namespaceStr, components[1])
	}
}
