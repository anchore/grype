package configwarn

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		app     string
		args    []string
		env     map[string]string
		present []string
		want    string
	}{
		{
			name:    "no file present, no flag, no env",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			present: nil,
			want:    "",
		},
		{
			name:    "cwd .grype.yaml present and no flag/env",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			present: []string{".grype.yaml"},
			want:    ".grype.yaml",
		},
		{
			name:    "cwd .grype.yml present and no flag/env",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			present: []string{".grype.yml"},
			want:    ".grype.yml",
		},
		{
			name:    "cwd .grype.json present and no flag/env",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			present: []string{".grype.json"},
			want:    ".grype.json",
		},
		{
			name:    "cwd .grype/config.yaml present and no flag/env",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			present: []string{filepath.Join(".grype", "config.yaml")},
			want:    filepath.Join(".grype", "config.yaml"),
		},
		{
			name:    "explicit --config suppresses warning",
			app:     "grype",
			args:    []string{"grype", "--config", "/etc/grype.yaml", "alpine:latest"},
			present: []string{".grype.yaml"},
			want:    "",
		},
		{
			name:    "explicit --config= suppresses warning",
			app:     "grype",
			args:    []string{"grype", "--config=/etc/grype.yaml", "alpine:latest"},
			present: []string{".grype.yaml"},
			want:    "",
		},
		{
			name:    "explicit -c suppresses warning",
			app:     "grype",
			args:    []string{"grype", "-c", "/etc/grype.yaml", "alpine:latest"},
			present: []string{".grype.yaml"},
			want:    "",
		},
		{
			name:    "explicit -c=path suppresses warning",
			app:     "grype",
			args:    []string{"grype", "-c=/etc/grype.yaml", "alpine:latest"},
			present: []string{".grype.yaml"},
			want:    "",
		},
		{
			name:    "explicit -cpath bundled short form suppresses warning",
			app:     "grype",
			args:    []string{"grype", "-c/etc/grype.yaml", "alpine:latest"},
			present: []string{".grype.yaml"},
			want:    "",
		},
		{
			name:    "GRYPE_CONFIG env suppresses warning",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			env:     map[string]string{"GRYPE_CONFIG": "/etc/grype.yaml"},
			present: []string{".grype.yaml"},
			want:    "",
		},
		{
			name:    "trailing -c with no value is not treated as explicit",
			app:     "grype",
			args:    []string{"grype", "alpine:latest", "-c"},
			present: []string{".grype.yaml"},
			want:    ".grype.yaml",
		},
		{
			name:    "subdir form is only checked after the flat form",
			app:     "grype",
			args:    []string{"grype", "alpine:latest"},
			present: []string{".grype.yaml", filepath.Join(".grype", "config.yaml")},
			want:    ".grype.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			present := map[string]struct{}{}
			for _, p := range tt.present {
				present[p] = struct{}{}
			}
			origExists := fileExists
			fileExists = func(path string) bool {
				_, ok := present[path]
				return ok
			}
			t.Cleanup(func() { fileExists = origExists })

			env := func(string) string { return "" }
			if tt.env != nil {
				env = func(k string) string { return tt.env[k] }
			}

			got := Detect(tt.app, tt.args, env)
			assert.Equal(t, tt.want, got)
		})
	}
}
