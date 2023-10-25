package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_javaVersion_Compare(t *testing.T) {
	tests := []struct {
		name    string
		compare string
		want    int
	}{
		{
			name:    "1",
			compare: "2",
			want:    1,
		},
		{
			name:    "1.8.0_282",
			compare: "1.8.0_282",
			want:    0,
		},
		{
			name:    "2.5",
			compare: "2.0",
			want:    -1,
		},
		{
			name:    "2.414.2-cb-5",
			compare: "2.414.2",
			want:    -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := NewVersion(tt.name, JavaFormat)
			assert.NoError(t, err)

			j2, err := NewVersion(tt.compare, JavaFormat)
			assert.NoError(t, err)

			if got, _ := j.rich.javaVer.Compare(j2); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
