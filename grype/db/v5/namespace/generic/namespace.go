package generic

import (
	"fmt"
	"github.com/anchore/grype/grype/db/v5/pkg/resolver"
	"github.com/anchore/grype/grype/db/v5/pkg/resolver/stock"
	"strings"
)

const ID = "generic"

type Namespace struct {
	provider string
}

func (n Namespace) Provider() string {
	return n.provider
}

func (n Namespace) Resolver() resolver.Resolver {
	// TODO: WILL: Do we need something else here?
	return &stock.Resolver{}
}

func (n Namespace) String() string {
	return fmt.Sprintf("%s:generic", n.provider)
}

func FromString(namespaceStr string) (*Namespace, error) {
	parts := strings.Split(namespaceStr, ":")
	if len(parts) != 2 || parts[1] != "generic" {
		return nil, fmt.Errorf("invalid string for generic namespace: %s", namespaceStr)
	}
	return &Namespace{provider: parts[0]}, nil
}
