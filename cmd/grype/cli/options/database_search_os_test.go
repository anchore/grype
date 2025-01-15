package options

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestDBSearchOSsPostLoad(t *testing.T) {
	testCases := []struct {
		name           string
		input          DBSearchOSs
		expectedSpecs  v6.OSSpecifiers
		expectedErrMsg string
	}{
		{
			name:          "no OS input (any OS)",
			input:         DBSearchOSs{},
			expectedSpecs: []*v6.OSSpecifier{v6.AnyOSSpecified},
		},
		{
			name: "valid OS name only",
			input: DBSearchOSs{
				OSs: []string{"ubuntu"},
			},
			expectedSpecs: []*v6.OSSpecifier{
				{Name: "ubuntu", AllowMultiple: true},
			},
		},
		{
			name: "valid OS with major version",
			input: DBSearchOSs{
				OSs: []string{"ubuntu@20"},
			},
			expectedSpecs: []*v6.OSSpecifier{
				{Name: "ubuntu", MajorVersion: "20", AllowMultiple: true},
			},
		},
		{
			name: "valid OS with major and minor version",
			input: DBSearchOSs{
				OSs: []string{"ubuntu@20.04"},
			},
			expectedSpecs: []*v6.OSSpecifier{
				{Name: "ubuntu", MajorVersion: "20", MinorVersion: "04", AllowMultiple: true},
			},
		},
		{
			name: "valid OS with codename",
			input: DBSearchOSs{
				OSs: []string{"ubuntu@focal"},
			},
			expectedSpecs: []*v6.OSSpecifier{
				{Name: "ubuntu", LabelVersion: "focal", AllowMultiple: true},
			},
		},
		{
			name: "invalid OS version (too many parts)",
			input: DBSearchOSs{
				OSs: []string{"ubuntu@20.04.1"},
			},
			expectedErrMsg: "invalid distro version provided: patch version ignored",
		},
		{
			name: "invalid OS format with colon",
			input: DBSearchOSs{
				OSs: []string{"ubuntu:20"},
			},
			expectedSpecs: []*v6.OSSpecifier{
				{Name: "ubuntu", MajorVersion: "20", AllowMultiple: true},
			},
		},
		{
			name: "invalid OS with empty version",
			input: DBSearchOSs{
				OSs: []string{"ubuntu@"},
			},
			expectedErrMsg: "invalid distro version provided",
		},
		{
			name: "invalid OS name@version format",
			input: DBSearchOSs{
				OSs: []string{"ubuntu@20@04"},
			},
			expectedErrMsg: "invalid distro name@version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.PostLoad()

			if tc.expectedErrMsg != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			if d := cmp.Diff(tc.expectedSpecs, tc.input.Specs); d != "" {
				t.Errorf("unexpected OS specifiers (-want +got):\n%s", d)
			}
		})
	}
}
