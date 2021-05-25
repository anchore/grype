package version

import (
	"testing"
)

func TestVersionRpm(t *testing.T) {
	tests := []struct {
		v1     string
		v2     string
		result int
	}{
		// from https://github.com/anchore/anchore-engine/blob/a447ee951c2d4e17c2672553d7280cfdb5e5f193/tests/unit/anchore_engine/util/test_rpm.py
		{"1", "1", 0},
		{"4.19.0a-1.el7_5", "4.19.0c-1.el7", -1},
		{"4.19.0-1.el7_5", "4.21.0-1.el7", -1},
		{"4.19.01-1.el7_5", "4.19.10-1.el7_5", -1},
		{"4.19.0-1.el7_5", "4.19.0-1.el7", 1},
		{"4.19.0-1.el7_5", "4.17.0-1.el7", 1},
		{"4.19.01-1.el7_5", "4.19.1-1.el7_5", 0},
		{"4.19.1-1.el7_5", "4.19.1-01.el7_5", 0},
		{"4.19.1", "4.19.1", 0},
		{"1.2.3-el7_5~snapshot1", "1.2.3-3-el7_5", -1},
		{"1:0", "0:1", 1},
		{"1:0", "1", 1},
		{"1:2", "1", 1},
		{"2:4.19.01-1.el7_5", "4.19.1-1.el7_5", 1},
		{"4.19.01-1.el7_5", "2:4.19.1-1.el7_5", -1},
		{"0:4.19.1-1.el7_5", "2:4.19.1-1.el7_5", -1},
		{"4.19.0-1.el7_5", "12:4.19.0-1.el7", -1},
		{"3:4.19.0-1.el7_5", "4.21.0-1.el7", 1},
		{"4:1.2.3-3-el7_5", "1.2.3-el7_5~snapshot1", 1},
	}

	for _, test := range tests {
		name := test.v1 + "_vs_" + test.v2
		t.Run(name, func(t *testing.T) {
			v1, err := newRpmVersion(test.v1)
			if err != nil {
				t.Fatalf("failed to create v1: %+v", err)
			}

			v2, err := newRpmVersion(test.v2)
			if err != nil {
				t.Fatalf("failed to create v2: %+v", err)
			}

			actual := v1.compare(v2)

			if actual != test.result {
				t.Errorf("bad result: %+v (expected: %+v)", actual, test.result)
			}
		})
	}
}
