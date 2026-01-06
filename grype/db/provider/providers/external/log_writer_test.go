package external

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogWriter_processLogLine(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		expectedLevel   string
		expectedMessage string
	}{
		{
			name:            "default log level",
			line:            `\033[0maggregating vulnerability data providers=[rhel]`,
			expectedLevel:   defaultLogLevel,
			expectedMessage: `\033[0maggregating vulnerability data providers=[rhel]`,
		},
		{
			name:            "info log level",
			line:            `\033[0m[INFO ] aggregating vulnerability data providers=[rhel]`,
			expectedLevel:   "INFO",
			expectedMessage: `\033[0maggregating vulnerability data providers=[rhel]`,
		},
		{
			name:            "warning log level",
			line:            `blah [WARNING] something could be going wrong`,
			expectedLevel:   "WARNING",
			expectedMessage: `blah something could be going wrong`,
		},
		{
			name:            "warn log level",
			line:            `blah [WARN ] something could be going wrong`,
			expectedLevel:   "WARN",
			expectedMessage: `blah something could be going wrong`,
		},
		{
			name:            "debug log level",
			line:            `abcdefg [DEBUG] jasdklfjlaksdjflksadj`,
			expectedLevel:   "DEBUG",
			expectedMessage: `abcdefg jasdklfjlaksdjflksadj`,
		},
		{
			name:            "trace log level",
			line:            `[TRACE] -----^^^^^`,
			expectedLevel:   "TRACE",
			expectedMessage: `-----^^^^^`,
		},
		{
			name:            "error log level",
			line:            `[ERROR] something bad happened`,
			expectedLevel:   "ERROR",
			expectedMessage: `something bad happened`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			level, message := processLogLine(test.line)
			assert.Equal(t, level, test.expectedLevel)
			assert.Equal(t, message, test.expectedMessage)
		})
	}
}
