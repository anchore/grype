package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasNonEmptyCredentials(t *testing.T) {
	tests := []struct {
		username, password, token string
		expected                  bool
	}{
		{
			"", "", "",
			false,
		},
		{
			"user", "", "",
			false,
		},
		{
			"", "pass", "",
			false,
		},
		{
			"", "pass", "tok",
			true,
		},
		{
			"user", "", "tok",
			true,
		},
		{
			"", "", "tok",
			true,
		},
		{
			"user", "pass", "tok",
			true,
		},

		{
			"user", "pass", "",
			true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			assert.Equal(t, test.expected, hasNonEmptyCredentials(test.username, test.password, test.token))
		})
	}
}
