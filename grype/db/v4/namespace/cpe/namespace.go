package cpe

import (
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/db/v4/namespace"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/stock"
	"strings"
)

type Namespace struct {
	provider      string
	namespaceType namespace.Type
	resolver      resolver.Resolver
}

func NewNamespace(provider string) *Namespace {
	return &Namespace{
		provider:      provider,
		namespaceType: namespace.CPE,
		resolver:      &stock.Resolver{},
	}
}

func FromString(namespaceStr string) (*Namespace, error) {
	if namespaceStr == "" {
		return nil, errors.New("unable to create CPE namespace from empty string")
	}

	components := strings.Split(namespaceStr, namespace.Separator)

	if len(components) != 2 {
		return nil, fmt.Errorf("unable to create CPE namespace from %s: incorrect number of components", namespaceStr)
	}

	if components[1] != string(namespace.CPE) {
		return nil, fmt.Errorf("unable to create CPE namespace from %s: type %s is incorrect", namespaceStr, components[1])
	}

	return NewNamespace(components[0]), nil
}

func (n *Namespace) Provider() string {
	return n.provider
}

func (n *Namespace) Type() namespace.Type {
	return n.namespaceType
}

func (n *Namespace) Resolver() resolver.Resolver {
	return n.resolver
}

func (n Namespace) String() string {
	return fmt.Sprintf("%s:%s", n.provider, n.namespaceType)
}
