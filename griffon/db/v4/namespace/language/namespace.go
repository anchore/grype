package language

import (
	"errors"
	"fmt"
	"strings"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nextlinux/griffon/griffon/db/v4/pkg/resolver"
)

const ID = "language"

type Namespace struct {
	provider    string
	language    syftPkg.Language
	packageType syftPkg.Type
	resolver    resolver.Resolver
}

func NewNamespace(provider string, language syftPkg.Language, packageType syftPkg.Type) *Namespace {
	r, _ := resolver.FromLanguage(language)

	return &Namespace{
		provider:    provider,
		language:    language,
		packageType: packageType,
		resolver:    r,
	}
}

func FromString(namespaceStr string) (*Namespace, error) {
	if namespaceStr == "" {
		return nil, errors.New("unable to create language namespace from empty string")
	}

	components := strings.Split(namespaceStr, ":")

	if len(components) != 3 && len(components) != 4 {
		return nil, fmt.Errorf("unable to create language namespace from %s: incorrect number of components", namespaceStr)
	}

	if components[1] != ID {
		return nil, fmt.Errorf("unable to create language namespace from %s: type %s is incorrect", namespaceStr, components[1])
	}

	packageType := ""

	if len(components) == 4 {
		packageType = components[3]
	}

	return NewNamespace(components[0], syftPkg.Language(components[2]), syftPkg.Type(packageType)), nil
}

func (n *Namespace) Provider() string {
	return n.provider
}

func (n *Namespace) Language() syftPkg.Language {
	return n.language
}

func (n *Namespace) PackageType() syftPkg.Type {
	return n.packageType
}

func (n *Namespace) Resolver() resolver.Resolver {
	return n.resolver
}

func (n Namespace) String() string {
	if n.packageType != "" {
		return fmt.Sprintf("%s:%s:%s:%s", n.provider, ID, n.language, n.packageType)
	}

	return fmt.Sprintf("%s:%s:%s", n.provider, ID, n.language)
}
