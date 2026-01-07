package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{
			input: "negLIGible",
			want:  SeverityNegligible,
		},
		{
			input: "loW",
			want:  SeverityLow,
		},
		{
			input: "meDIum",
			want:  SeverityMedium,
		},
		{
			input: "  hiGH",
			want:  SeverityHigh,
		},
		{
			input: "cRiTical  ",
			want:  SeverityCritical,
		},
		{
			input: "unKNOWN",
			want:  SeverityUnknown,
		},
		{
			input: "",
			want:  SeverityUnknown,
		},
		{
			input: "  ",
			want:  SeverityUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseSeverity(tt.input))
		})
	}
}
