package file

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetter_GetFile(t *testing.T) {
	testCases := []struct {
		name          string
		prepareClient func(*http.Client)
		assert        assert.ErrorAssertionFunc
	}{
		{
			name:   "client trusts server's CA",
			assert: assert.NoError,
		},
		{
			name:          "client doesn't trust server's CA",
			prepareClient: removeTrustedCAs,
			assert:        assertUnknownAuthorityError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestPath := "/foo"

			server := newTestServer(t, withResponseForPath(t, requestPath, testFileContent))
			t.Cleanup(server.Close)

			httpClient := getClient(t, server)
			if tc.prepareClient != nil {
				tc.prepareClient(httpClient)
			}

			getter := NewGetter(httpClient)
			requestURL := createRequestURL(t, server, requestPath)

			tempDir := t.TempDir()
			tempFile := path.Join(tempDir, "some-destination-file")

			err := getter.GetFile(tempFile, requestURL)
			tc.assert(t, err)
		})
	}
}

func TestGetter_GetToDir_FilterNonArchives(t *testing.T) {
	testCases := []struct {
		name   string
		source string
		assert assert.ErrorAssertionFunc
	}{
		{
			name:   "error out on non-archive sources for dir fetching",
			source: "http://localhost/something.txt",
			assert: assertErrNonArchiveSource,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			test.assert(t, NewGetter(nil).GetToDir(t.TempDir(), test.source))
		})
	}
}

func TestGetter_GetToDir_CAconcerns(t *testing.T) {
	testCases := []struct {
		name          string
		prepareClient func(*http.Client)
		assert        assert.ErrorAssertionFunc
	}{

		{
			name:   "client trusts server's CA",
			assert: assert.NoError,
		},
		{
			name:          "client doesn't trust server's CA",
			prepareClient: removeTrustedCAs,
			assert:        assertUnknownAuthorityError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestPath := "/foo.tar"
			tarball := createTarball("foo", testFileContent)

			server := newTestServer(t, withResponseForPath(t, requestPath, tarball))
			t.Cleanup(server.Close)

			httpClient := getClient(t, server)
			if tc.prepareClient != nil {
				tc.prepareClient(httpClient)
			}

			getter := NewGetter(httpClient)
			requestURL := createRequestURL(t, server, requestPath)

			tempDir := t.TempDir()

			err := getter.GetToDir(tempDir, requestURL)
			tc.assert(t, err)
		})
	}
}

func assertUnknownAuthorityError(t assert.TestingT, err error, _ ...interface{}) bool {
	return assert.ErrorAs(t, err, &x509.UnknownAuthorityError{})
}

func assertErrNonArchiveSource(t assert.TestingT, err error, _ ...interface{}) bool {
	return assert.ErrorIs(t, err, ErrNonArchiveSource)
}

func removeTrustedCAs(client *http.Client) {
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = nil
}

// createTarball makes a single-file tarball and returns it as a byte slice.
func createTarball(filename string, content []byte) []byte {
	tarBuffer := new(bytes.Buffer)
	tarWriter := tar.NewWriter(tarBuffer)
	tarWriter.WriteHeader(&tar.Header{
		Name: filename,
		Size: int64(len(content)),
		Mode: 0600,
	})
	tarWriter.Write(content)
	tarWriter.Close()

	return tarBuffer.Bytes()
}

type muxOption func(mux *http.ServeMux)

func withResponseForPath(t *testing.T, path string, response []byte) muxOption {
	t.Helper()

	return func(mux *http.ServeMux) {
		mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			t.Logf("server handling request: %s %s", req.Method, req.URL)

			_, err := w.Write(response)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func newTestServer(t *testing.T, muxOptions ...muxOption) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	for _, option := range muxOptions {
		option(mux)
	}

	server := httptest.NewTLSServer(mux)
	t.Logf("new TLS server listening at %s", getHost(t, server))

	return server
}

func createRequestURL(t *testing.T, server *httptest.Server, path string) string {
	t.Helper()

	// TODO: Figure out how to get this value from the server without hardcoding it here
	const testServerCertificateName = "example.com"

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Set URL hostname to value from TLS certificate
	serverURL.Host = fmt.Sprintf("%s:%s", testServerCertificateName, serverURL.Port())

	serverURL.Path = path

	return serverURL.String()
}

// getClient returns an http.Client that can be used to contact the test TLS server.
func getClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()

	httpClient := server.Client()
	transport := httpClient.Transport.(*http.Transport)

	serverHost := getHost(t, server)

	transport.DialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
		t.Logf("client dialing %q for host %q", serverHost, addr)

		// Ensure the client dials our test server
		return net.Dial("tcp", serverHost)
	}

	return httpClient
}

// getHost extracts the host value from a server URL string.
// e.g. given a server with URL "http://1.2.3.4:5000/foo", getHost returns "1.2.3.4:5000"
func getHost(t *testing.T, server *httptest.Server) string {
	t.Helper()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	return u.Hostname() + ":" + u.Port()
}

var testFileContent = []byte("This is the content of a test file!\n")
