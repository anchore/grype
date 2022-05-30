package stock

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Normalize(t *testing.T) {
	tests := []struct {
		packageName    string
		normalizedName string
	}{
		{
			packageName:    "PyYAML",
			normalizedName: "pyyaml",
		},
		{
			packageName:    "oslo.concurrency",
			normalizedName: "oslo.concurrency",
		},
		{
			packageName:    "",
			normalizedName: "",
		},
		{
			packageName:    "test---1",
			normalizedName: "test---1",
		},
		{
			packageName:    "AbCd.-__.--.-___.__.--1234____----....XyZZZ",
			normalizedName: "abcd.-__.--.-___.__.--1234____----....xyzzz",
		},
	}

	namer := Namer{}

	for _, test := range tests {
		normalizedName, _ := namer.Normalize(test.packageName)
		assert.Equal(t, normalizedName, test.normalizedName)
	}
}
