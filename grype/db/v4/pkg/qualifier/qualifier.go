package qualifier

import (
	"fmt"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

type Qualifier interface {
	fmt.Stringer
	Parse() qualifier.Qualifier
}
