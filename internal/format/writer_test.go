package format

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/pkg/homedir"
	"github.com/stretchr/testify/assert"
)

func Test_MakeScanResultWriter(t *testing.T) {
	tests := []struct {
		outputs []string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			outputs: []string{"json"},
			wantErr: assert.NoError,
		},
		{
			outputs: []string{"table", "json"},
			wantErr: assert.NoError,
		},
		{
			outputs: []string{"unknown"},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, `unsupported output format "unknown", supported formats are: [`)
			},
		},
	}

	for _, tt := range tests {
		_, err := MakeScanResultWriter(tt.outputs, "", PresentationConfig{})
		tt.wantErr(t, err)
	}
}

func Test_newSBOMMultiWriter(t *testing.T) {
	type writerConfig struct {
		format string
		file   string
	}

	tmp := t.TempDir()

	testName := func(options []scanResultWriterDescription, err bool) string {
		var out []string
		for _, opt := range options {
			out = append(out, opt.Format.String()+"="+opt.Path)
		}
		errs := ""
		if err {
			errs = "(err)"
		}
		return strings.Join(out, ", ") + errs
	}

	tests := []struct {
		outputs  []scanResultWriterDescription
		err      bool
		expected []writerConfig
	}{
		{
			outputs: []scanResultWriterDescription{},
			err:     true,
		},
		{
			outputs: []scanResultWriterDescription{
				{
					Format: Format{name: "table", version: ""},
					Path:   "",
				},
			},
			expected: []writerConfig{
				{
					format: "table",
				},
			},
		},
		{
			outputs: []scanResultWriterDescription{
				{
					Format: Format{name: "json", version: ""},
				},
			},
			expected: []writerConfig{
				{
					format: "json",
				},
			},
		},
		{
			outputs: []scanResultWriterDescription{
				{
					Format: Format{name: "json", version: ""},
					Path:   "test-2.json",
				},
			},
			expected: []writerConfig{
				{
					format: "json",
					file:   "test-2.json",
				},
			},
		},
		{
			outputs: []scanResultWriterDescription{
				{
					Format: Format{name: "json", version: ""},
					Path:   "test-3/1.json",
				},
				{
					Format: Format{name: "spdx-json", version: ""},
					Path:   "test-3/2.json",
				},
			},
			expected: []writerConfig{
				{
					format: "json",
					file:   "test-3/1.json",
				},
				{
					format: "spdx-json",
					file:   "test-3/2.json",
				},
			},
		},
		{
			outputs: []scanResultWriterDescription{
				{
					Format: Format{name: "text", version: ""},
				},
				{
					Format: Format{name: "spdx-json", version: ""},
					Path:   "test-4.json",
				},
			},
			expected: []writerConfig{
				{
					format: "text",
				},
				{
					format: "spdx-json",
					file:   "test-4.json",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(testName(test.outputs, test.err), func(t *testing.T) {
			outputs := test.outputs
			for i := range outputs {
				if outputs[i].Path != "" {
					outputs[i].Path = tmp + outputs[i].Path
				}
			}

			mw, err := newMultiWriter(outputs...)

			if test.err {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, mw.writers, len(test.expected))

			for i, e := range test.expected {
				switch w := mw.writers[i].(type) {
				case *scanResultStreamWriter:
					assert.Equal(t, w.format.String(), e.format)
					assert.NotNil(t, w.out)
					if e.file != "" {
						assert.FileExists(t, tmp+e.file)
					}
				case *scanResultPublisher:
					assert.Equal(t, w.format.String(), e.format)
				default:
					t.Fatalf("unknown writer type: %T", w)
				}

			}
		})
	}
}

func Test_newSBOMWriterDescription(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "expand home dir",
			path:     "~/place.txt",
			expected: filepath.Join(homedir.Get(), "place.txt"),
		},
		{
			name:     "passthrough other paths",
			path:     "/other/place.txt",
			expected: "/other/place.txt",
		},
		{
			name:     "no path",
			path:     "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newWriterDescription(Format{name: "table", version: ""}, tt.path, PresentationConfig{})
			assert.Equal(t, tt.expected, o.Path)
		})
	}
}
