package file

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/spf13/afero"
)

func CopyDir(fs afero.Fs, src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = fs.Stat(src); err != nil {
		return err
	}

	if err = fs.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcPath := path.Join(src, fd.Name())
		dstPath := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = CopyDir(fs, srcPath, dstPath); err != nil {
				return fmt.Errorf("could not copy dir (%s -> %s): %w", srcPath, dstPath, err)
			}
		} else {
			if err = CopyFile(fs, srcPath, dstPath); err != nil {
				return fmt.Errorf("could not copy file (%s -> %s): %w", srcPath, dstPath, err)
			}
		}
	}
	return nil
}

func CopyFile(fs afero.Fs, src, dst string) error {
	var err error
	var srcFd afero.File
	var dstFd afero.File
	var srcinfo os.FileInfo

	if srcFd, err = fs.Open(src); err != nil {
		return err
	}
	defer srcFd.Close()

	if dstFd, err = fs.Create(dst); err != nil {
		return err
	}
	defer dstFd.Close()

	if _, err = io.Copy(dstFd, srcFd); err != nil {
		return err
	}
	if srcinfo, err = fs.Stat(src); err != nil {
		return err
	}
	return fs.Chmod(dst, srcinfo.Mode())
}
