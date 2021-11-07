package file

import (
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-getter"
	"github.com/wagoodman/go-progress"
)

type Getter interface {
	// GetFile downloads the give URL into the given path. The URL must reference a single file.
	GetFile(dst, src string, monitor ...*progress.Manual) error

	// GetToDir downloads the resource found at the `src` URL into the given `dst` directory.
	// The directory must already exist, and the remote resource MUST BE AN ARCHIVE (e.g. `.tar.gz`).
	GetToDir(dst, src string, monitor ...*progress.Manual) error
}

type HashiGoGetter struct {
	httpGetter getter.HttpGetter
}

// NewGetter creates and returns a new Getter. Providing an http.Client is optional. If one is provided,
// it will be used for all HTTP(S) getting; otherwise, go-getter's default getters will be used.
func NewGetter(httpClient *http.Client) *HashiGoGetter {
	return &HashiGoGetter{
		httpGetter: getter.HttpGetter{
			Client: httpClient,
		},
	}
}

func (g HashiGoGetter) GetFile(dst, src string, monitors ...*progress.Manual) error {
	if len(monitors) > 1 {
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}

	return getterClient(dst, src, false, g.httpGetter, monitors).Get()
}

func (g HashiGoGetter) GetToDir(dst, src string, monitors ...*progress.Manual) error {
	if len(monitors) > 1 {
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}

	return getterClient(dst, src, true, g.httpGetter, monitors).Get()
}

func getterClient(dst, src string, dir bool, httpGetter getter.HttpGetter, monitors []*progress.Manual) *getter.Client {
	client := &getter.Client{
		Src: src,
		Dst: dst,
		Dir: dir,
		Getters: map[string]getter.Getter{
			"http":  &httpGetter,
			"https": &httpGetter,
		},
		Options: mapToGetterClientOptions(monitors),
	}

	return client
}

func withProgress(monitor *progress.Manual) func(client *getter.Client) error {
	return getter.WithProgress(
		&progressAdapter{monitor: monitor},
	)
}

func mapToGetterClientOptions(monitors []*progress.Manual) []getter.ClientOption {
	// TODO: This function is no longer needed once a generic `map` method is available.

	var result []getter.ClientOption

	for _, monitor := range monitors {
		result = append(result, withProgress(monitor))
	}

	return result
}

type readCloser struct {
	progress.Reader
}

func (c *readCloser) Close() error { return nil }

type progressAdapter struct {
	monitor *progress.Manual
}

func (a *progressAdapter) TrackProgress(_ string, currentSize, totalSize int64, stream io.ReadCloser) io.ReadCloser {
	a.monitor.N = currentSize
	a.monitor.Total = totalSize
	return &readCloser{
		Reader: *progress.NewProxyReader(stream, a.monitor),
	}
}
