package file

import (
	"os"

	"github.com/spf13/afero"
)

func Exists(fs afero.Fs, path string) (bool, error) {
	info, err := fs.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return !info.IsDir(), nil
}
