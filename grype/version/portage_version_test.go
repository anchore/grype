package version

import (
	"testing"
)

func TestVersionPortage(t *testing.T) {
	tests := []struct {
		v1     string
		v2     string
		result int
	}{
		{"1", "1", 0},
		{"12.2.5", "12.2b", 1},
		{"12.2a", "12.2b", -1},
		{"12.2", "12.2.0", -1},
		{"1.01", "1.1", -1},
		{"1_p1", "1_p0", 1},
		{"1_p0", "1", 1},
		{"1-r1", "1", 1},
		{"1.2.3-r2", "1.2.3-r1", 1},
		{"1.2.3-r1", "1.2.3-r2", -1},
	}

	for _, test := range tests {
		name := test.v1 + "_vs_" + test.v2
		t.Run(name, func(t *testing.T) {
			v1 := newPortageVersion(test.v1)
			v2 := newPortageVersion(test.v2)

			actual := v1.compare(v2)

			if actual != test.result {
				t.Errorf("bad result: %+v (expected: %+v)", actual, test.result)
			}
		})
	}
}
