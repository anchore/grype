package file

import (
	"os"

	"github.com/spf13/afero"
)

func Exists(fs afero.Fs, path string) bool {
	info, err := fs.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
