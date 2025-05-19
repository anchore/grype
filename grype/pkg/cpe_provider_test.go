package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_CPEProvider(t *testing.T) {
	tests := []struct {
		name      string
		userInput string
		context   Context
		pkgs      []Package
		sbom      *sbom.SBOM
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name:      "takes a single cpe",
			userInput: "cpe:/a:apache:log4j:2.14.1",
			context: Context{
				Source: &source.Description{
					Metadata: CPELiteralMetadata{
						CPE: "cpe:/a:apache:log4j:2.14.1",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "log4j",
					Version: "2.14.1",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:/a:apache:log4j:2.14.1", ""),
					},
				},
			},
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "log4j",
						Version: "2.14.1",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:/a:apache:log4j:2.14.1", ""),
						},
					}),
				},
			},
		},
		{
			name:      "takes cpe with no version",
			userInput: "cpe:/a:apache:log4j",
			context: Context{
				Source: &source.Description{
					Metadata: CPELiteralMetadata{
						CPE: "cpe:/a:apache:log4j",
					},
				},
			},
			pkgs: []Package{
				{
					Name: "log4j",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:/a:apache:log4j", ""),
					},
				},
			},
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name: "log4j",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:/a:apache:log4j", ""),
						},
					}),
				},
			},
		},
		{
			name:      "takes CPE 2.3 format",
			userInput: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			context: Context{
				Source: &source.Description{
					Metadata: CPELiteralMetadata{
						CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "log4j",
					Version: "2.14.1",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", ""),
					},
				},
			},
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "log4j",
						Version: "2.14.1",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", ""),
						},
					}),
				},
			},
		},

		{
			name:      "invalid prefix",
			userInput: "dir:test-fixtures/cpe",
			wantErr:   require.Error,
		},
	}

	opts := []cmp.Option{
		cmpopts.IgnoreFields(Package{}, "ID", "Locations", "Licenses", "Metadata", "Type", "Language"),
	}

	syftPkgOpts := []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id", "Type", "Language"),
		cmpopts.IgnoreUnexported(pkg.Package{}, file.LocationSet{}, pkg.LicenseSet{}),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}

			packages, ctx, gotSBOM, err := cpeProvider(tc.userInput)

			tc.wantErr(t, err)
			if err != nil {
				require.Nil(t, packages)
				return
			}

			if d := cmp.Diff(tc.context, ctx, opts...); d != "" {
				t.Errorf("unexpected context (-want +got):\n%s", d)
			}

			require.Len(t, packages, len(tc.pkgs))
			for idx, expected := range tc.pkgs {
				if d := cmp.Diff(expected, packages[idx], opts...); d != "" {
					t.Errorf("unexpected package (-want +got):\n%s", d)
				}
			}

			gotSyftPkgs := gotSBOM.Artifacts.Packages.Sorted()
			wantSyftPkgs := tc.sbom.Artifacts.Packages.Sorted()
			require.Equal(t, len(gotSyftPkgs), len(wantSyftPkgs))
			for idx, wantPkg := range wantSyftPkgs {
				if d := cmp.Diff(wantPkg, gotSyftPkgs[idx], syftPkgOpts...); d != "" {
					t.Errorf("unexpected Syft Package (-want +got):\n%s", d)
				}
			}
		})
	}
}
