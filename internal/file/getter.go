package file

import (
	"fmt"
	"io"

	"github.com/hashicorp/go-getter"
	"github.com/wagoodman/go-progress"
)

type Getter interface {
	// GetFile downloads the give URL into the given path. The URL must reference a single file.
	GetFile(dst, src string, monitor ...*progress.Manual) error

	// Get downloads the given URL into the given directory. The directory must already exist.
	GetToDir(dst, src string, monitor ...*progress.Manual) error
}

type HashiGoGetter struct {
}

type progressAdapter struct {
	monitor *progress.Manual
}

func NewGetter() *HashiGoGetter {
	return &HashiGoGetter{}
}

func (g HashiGoGetter) GetFile(dst, src string, monitors ...*progress.Manual) error {
	switch len(monitors) {
	case 0:
		return getter.GetFile(dst, src)
	case 1:
		return getter.GetFile(dst, src,
			getter.WithProgress(
				&progressAdapter{
					monitor: monitors[0],
				},
			),
		)
	default:
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}
}

func (g HashiGoGetter) GetToDir(dst, src string, monitors ...*progress.Manual) error {
	switch len(monitors) {
	case 0:
		return getter.Get(dst, src)
	case 1:

		return getter.Get(dst, src,
			getter.WithProgress(
				&progressAdapter{
					monitor: monitors[0],
				},
			),
		)
	default:
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}
}

type readCloser struct {
	progress.Reader
}

func (c *readCloser) Close() error { return nil }

func (a *progressAdapter) TrackProgress(_ string, currentSize, totalSize int64, stream io.ReadCloser) io.ReadCloser {
	a.monitor.N = currentSize
	a.monitor.Total = totalSize
	return &readCloser{
		Reader: *progress.NewProxyReader(stream, a.monitor),
	}
}
