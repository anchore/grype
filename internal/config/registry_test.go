package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasNonEmptyCredentials(t *testing.T) {
	tests := []struct {
		auth, username, password, token string
		expected                        bool
	}{
		{
			"", "", "", "",
			false,
		},
		{
			"auth", "", "", "",
			false,
		},
		{
			"auth", "user", "", "",
			false,
		},
		{
			"auth", "", "pass", "",
			false,
		},
		{
			"auth", "", "pass", "tok",
			true,
		},
		{
			"auth", "user", "", "tok",
			true,
		},
		{
			"auth", "", "", "tok",
			true,
		},
		{
			"auth", "user", "pass", "tok",
			true,
		},

		{
			"auth", "user", "pass", "",
			true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			assert.Equal(t, test.expected, hasNonEmptyCredentials(test.auth, test.username, test.password, test.token))
		})
	}
}
