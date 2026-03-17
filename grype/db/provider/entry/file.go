package entry

import (
	"io"
	"os"
)

type fileOpener struct {
	path string
}

func fileOpeners(resultPaths []string) <-chan Opener {
	openers := make(chan Opener)
	go func() {
		defer close(openers)
		for _, p := range resultPaths {
			openers <- fileOpener{path: p}
		}
	}()
	return openers
}

func (e fileOpener) Open() (io.ReadCloser, error) {
	return os.Open(e.path)
}

func (e fileOpener) String() string {
	return e.path
}
