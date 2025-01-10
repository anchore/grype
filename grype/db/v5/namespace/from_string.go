package namespace

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/v5/namespace/cpe"
	"github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
)

func FromString(namespaceStr string) (Namespace, error) {
	if namespaceStr == "" {
		return nil, errors.New("unable to create namespace from empty string")
	}

	components := strings.Split(namespaceStr, ":")

	if len(components) < 2 {
		return nil, fmt.Errorf("unable to create namespace from %s: incorrect number of components", namespaceStr)
	}

	switch components[1] {
	case cpe.ID:
		return cpe.FromComponents(components)
	case distro.ID:
		return distro.FromComponents(components)
	case language.ID:
		return language.FromComponents(components)
	default:
		return nil, fmt.Errorf("unable to create namespace from %s: unknown type %s", namespaceStr, components[1])
	}
}
