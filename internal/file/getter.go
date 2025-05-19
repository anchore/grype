package file

import (
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-getter"
	"github.com/hashicorp/go-getter/helper/url"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/stereoscope/pkg/file"
)

var (
	archiveExtensions   = getterDecompressorNames()
	ErrNonArchiveSource = fmt.Errorf("non-archive sources are not supported for directory destinations")
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
func NewGetter(id clio.Identification, httpClient *http.Client) *HashiGoGetter {
	return &HashiGoGetter{
		httpGetter: getter.HttpGetter{
			Client: httpClient,
			Header: http.Header{
				"User-Agent": []string{fmt.Sprintf("%v %v", id.Name, id.Version)},
			},
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
	// though there are multiple getters, only the http/https getter requires extra validation
	if err := validateHTTPSource(src); err != nil {
		return err
	}
	if len(monitors) > 1 {
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}

	return getterClient(dst, src, true, g.httpGetter, monitors).Get()
}

func validateHTTPSource(src string) error {
	// we are ignoring any sources that are not destined to use the http getter object
	if !stringutil.HasAnyOfPrefixes(src, "http://", "https://") {
		return nil
	}

	u, err := url.Parse(src)
	if err != nil {
		return fmt.Errorf("bad URL provided %q: %w", src, err)
	}
	// only allow for sources with archive extensions
	if !stringutil.HasAnyOfSuffixes(u.Path, archiveExtensions...) {
		return ErrNonArchiveSource
	}
	return nil
}

func getterClient(dst, src string, dir bool, httpGetter getter.HttpGetter, monitors []*progress.Manual) *getter.Client {
	client := &getter.Client{
		Src: src,
		Dst: dst,
		Dir: dir,
		Getters: map[string]getter.Getter{
			"http":  &httpGetter,
			"https": &httpGetter,
			// note: these are the default getters from https://github.com/hashicorp/go-getter/blob/v1.5.9/get.go#L68-L74
			// it is possible that other implementations need to account for custom httpclient injection, however,
			// that has not been accounted for at this time.
			"file": new(getter.FileGetter),
			"git":  new(getter.GitGetter),
			"gcs":  new(getter.GCSGetter),
			"hg":   new(getter.HgGetter),
			"s3":   new(getter.S3Getter),
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
	var result []getter.ClientOption

	for _, monitor := range monitors {
		result = append(result, withProgress(monitor))
	}

	// derived from https://github.com/hashicorp/go-getter/blob/v2.2.3/decompress.go#L23-L63
	fileSizeLimit := int64(5 * file.GB)

	dec := getter.LimitedDecompressors(0, fileSizeLimit)
	fs := afero.NewOsFs()
	xzd := &xzDecompressor{
		FileSizeLimit: fileSizeLimit,
		Fs:            fs,
	}
	txzd := &tarXzDecompressor{
		FilesLimit:    0,
		FileSizeLimit: fileSizeLimit,
		Fs:            fs,
	}

	dec["xz"] = xzd
	dec["tar.xz"] = txzd
	dec["txz"] = txzd

	result = append(result, getter.WithDecompressors(dec))

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
	a.monitor.Set(currentSize)
	a.monitor.SetTotal(totalSize)
	return &readCloser{
		Reader: *progress.NewProxyReader(stream, a.monitor),
	}
}

func getterDecompressorNames() (names []string) {
	for name := range getter.Decompressors {
		names = append(names, name)
	}
	return names
}
