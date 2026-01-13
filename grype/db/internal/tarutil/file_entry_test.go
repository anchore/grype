package tarutil

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ lowLevelWriter = (*mockTarWriter)(nil)

type mockTarWriter struct {
	headers     []*tar.Header
	buffers     []*bytes.Buffer
	closeCalled bool
	flushCalled bool
	closeErr    error
	flushErr    error
}

func (m *mockTarWriter) Flush() error {
	m.flushCalled = true
	return m.flushErr
}

func (m *mockTarWriter) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockTarWriter) WriteHeader(header *tar.Header) error {
	m.headers = append(m.headers, header)
	m.buffers = append(m.buffers, &bytes.Buffer{})
	return nil
}

func (m *mockTarWriter) Write(b []byte) (int, error) {
	return m.buffers[len(m.buffers)-1].Write(b)
}

func TestFileEntry_writeEntry(t *testing.T) {
	testStr := "hello world"
	tests := []struct {
		name    string
		file    func(t *testing.T) string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "valid file",
			file: func(t *testing.T) string {
				dir := t.TempDir()
				dest := filepath.Join(dir, "file.txt")
				require.NoError(t, os.WriteFile(dest, []byte(testStr), 0644))
				return dest
			},
		},
		{
			name: "invalid file",
			file: func(t *testing.T) string {
				return filepath.Join("/tmp/invalid/path", uuid.New().String())
			},
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			expectedName := tt.file(t)
			fe := NewEntryFromFilePath(expectedName)
			tw := &mockTarWriter{}

			err := fe.writeEntry(tw)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			assert.NoError(t, err)
			require.Len(t, tw.headers, 1)
			assert.Equal(t, expectedName, tw.headers[0].Name)
			assert.Equal(t, int64(len(testStr)), tw.headers[0].Size)
			assert.Equal(t, testStr, tw.buffers[0].String())
		})
	}
}
