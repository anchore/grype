package qualifier

import (
	"fmt"

	"github.com/nextlinux/griffon/griffon/pkg/qualifier"
)

type Qualifier interface {
	fmt.Stringer
	Parse() qualifier.Qualifier
}
