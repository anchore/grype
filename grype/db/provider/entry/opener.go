package entry

import (
	"fmt"
	"io"
)

type Opener interface {
	Open() (io.ReadCloser, error)
	fmt.Stringer
}

func Openers(store string, resultPaths []string) (<-chan Opener, int64, error) {
	switch store {
	case "flat-file":
		return fileOpeners(resultPaths), int64(len(resultPaths)), nil
	case "sqlite":
		return sqliteOpeners(resultPaths)
	}
	return nil, 0, fmt.Errorf("unknown store: %q", store)
}

func Count(store string, resultPaths []string) (int64, error) {
	switch store {
	case "flat-file":
		return int64(len(resultPaths)), nil
	case "sqlite":
		return sqliteEntryCount(resultPaths)
	}
	return 0, fmt.Errorf("unknown store: %q", store)
}
