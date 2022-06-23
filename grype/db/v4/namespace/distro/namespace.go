package distro

import (
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/stock"
	"github.com/anchore/grype/grype/distro"
	"strings"
)

const ID = "distro"

type Namespace struct {
	provider   string
	distroType distro.Type
	version    string
	resolver   resolver.Resolver
}

func NewNamespace(provider string, distroType distro.Type, version string) *Namespace {
	return &Namespace{
		provider:   provider,
		distroType: distroType,
		version:    version,
		resolver:   &stock.Resolver{},
	}
}

func FromString(namespaceStr string) (*Namespace, error) {
	if namespaceStr == "" {
		return nil, errors.New("unable to create distro namespace from empty string")
	}

	components := strings.Split(namespaceStr, ":")

	if len(components) != 4 {
		return nil, fmt.Errorf("unable to create distro namespace from %s: incorrect number of components", namespaceStr)
	}

	if components[1] != ID {
		return nil, fmt.Errorf("unable to create distro namespace from %s: type %s is incorrect", namespaceStr, components[1])
	}

	return NewNamespace(components[0], distro.Type(components[2]), components[3]), nil
}

func (n *Namespace) Provider() string {
	return n.provider
}

func (n *Namespace) DistroType() distro.Type {
	return n.distroType
}

func (n *Namespace) Version() string {
	return n.version
}

func (n *Namespace) Resolver() resolver.Resolver {
	return n.resolver
}

func (n Namespace) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", n.provider, ID, n.distroType, n.version)
}
