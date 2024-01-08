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
			want:    -1,
		},
		{
			name:    "1.8.0_282",
			compare: "1.8.0_282",
			want:    0,
		},
		{
			name:    "2.5",
			compare: "2.0",
			want:    1,
		},
		{
			name:    "2.414.2-cb-5",
			compare: "2.414.2",
			want:    1,
		},
		{
			name:    "5.2.25.RELEASE", // see https://mvnrepository.com/artifact/org.springframework/spring-web
			compare: "5.2.25",
			want:    0,
		},
		{
			name:    "5.2.25.release",
			compare: "5.2.25",
			want:    0,
		},
		{
			name:    "5.2.25.FINAL",
			compare: "5.2.25",
			want:    0,
		},
		{
			name:    "5.2.25.final",
			compare: "5.2.25",
			want:    0,
		},
		{
			name:    "5.2.25.GA",
			compare: "5.2.25",
			want:    0,
		},
		{
			name:    "5.2.25.ga",
			compare: "5.2.25",
			want:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := NewVersion(tt.name, MavenFormat)
			assert.NoError(t, err)

			j2, err := NewVersion(tt.compare, MavenFormat)
			assert.NoError(t, err)

			if got, _ := j2.rich.mavenVer.Compare(j); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
