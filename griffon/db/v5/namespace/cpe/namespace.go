package cpe

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nextlinux/griffon/griffon/db/v5/pkg/resolver"
	"github.com/nextlinux/griffon/griffon/db/v5/pkg/resolver/stock"
)

const ID = "cpe"

type Namespace struct {
	provider string
	resolver resolver.Resolver
}

func NewNamespace(provider string) *Namespace {
	return &Namespace{
		provider: provider,
		resolver: &stock.Resolver{},
	}
}

func FromString(namespaceStr string) (*Namespace, error) {
	if namespaceStr == "" {
		return nil, errors.New("unable to create CPE namespace from empty string")
	}

	components := strings.Split(namespaceStr, ":")

	if len(components) != 2 {
		return nil, fmt.Errorf("unable to create CPE namespace from %s: incorrect number of components", namespaceStr)
	}

	if components[1] != ID {
		return nil, fmt.Errorf("unable to create CPE namespace from %s: type %s is incorrect", namespaceStr, components[1])
	}

	return NewNamespace(components[0]), nil
}

func (n *Namespace) Provider() string {
	return n.provider
}

func (n *Namespace) Resolver() resolver.Resolver {
	return n.resolver
}

func (n Namespace) String() string {
	return fmt.Sprintf("%s:%s", n.provider, ID)
}
