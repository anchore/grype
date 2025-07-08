package provider

import (
	"fmt"
	"io"
)

type Opener interface {
	Open() (io.ReadCloser, error)
	fmt.Stringer
}
