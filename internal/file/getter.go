package file

import "github.com/hashicorp/go-getter"

type Getter interface {
	// GetFile downloads the give URL into the given path. The URL must reference a single file.
	GetFile(dst, src string) error

	// Get downloads the given URL into the given directory. The directory must already exist.
	GetToDir(dst, src string) error
}

type HashiGoGetter struct {
}

func (g HashiGoGetter) GetFile(dst, src string) error {
	return getter.GetFile(dst, src)
}

func (g HashiGoGetter) GetToDir(dst, src string) error {
	return getter.Get(dst, src)
}
