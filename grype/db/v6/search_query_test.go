package v6

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestNewSearchCriteria(t *testing.T) {
	tests := []struct {
		name     string
		criteria []vulnerability.Criteria
		validate func(t *testing.T, input *searchQuery)
	}{
		{
			name: "package name criteria sets correct fields",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-package"),
			},
			validate: func(t *testing.T, input *searchQuery) {
				require.NotNil(t, input.pkgSpec)
				require.Equal(t, "test-package", input.pkgSpec.Name)
			},
		},
		{
			name: "unaffected criteria sets flag",
			criteria: []vulnerability.Criteria{
				search.ForUnaffected(),
			},
			validate: func(t *testing.T, input *searchQuery) {
				require.True(t, input.unaffectedOnly)
			},
		},
		{
			name: "ecosystem criteria sets package type and ecosystem",
			criteria: []vulnerability.Criteria{
				search.ByEcosystem(syftPkg.Java, syftPkg.JavaPkg),
			},
			validate: func(t *testing.T, input *searchQuery) {
				require.NotNil(t, input.pkgSpec)
				require.Equal(t, syftPkg.JavaPkg, input.pkgType)
				require.Equal(t, "java-archive", input.pkgSpec.Ecosystem)
			},
		},
		{
			name: "ID criteria adds vulnerability spec",
			criteria: []vulnerability.Criteria{
				search.ByID("CVE-2021-1234"),
			},
			validate: func(t *testing.T, input *searchQuery) {
				require.Len(t, input.vulnSpecs, 1)
				require.Equal(t, "CVE-2021-1234", input.vulnSpecs[0].Name)
			},
		},
		{
			name: "distro criteria sets OS specs",
			criteria: []vulnerability.Criteria{
				search.ByDistro(*distro.New(distro.Ubuntu, "20.04", "")),
			},
			validate: func(t *testing.T, input *searchQuery) {
				require.Len(t, input.osSpecs, 1)
				require.Equal(t, "ubuntu", input.osSpecs[0].Name)
				require.Equal(t, "20", input.osSpecs[0].MajorVersion)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, _, err := newSearchQuery(test.criteria)
			require.NoError(t, err)
			test.validate(t, query)
		})
	}
}

func TestQueryBuilder_ApplyCriteria(t *testing.T) {
	tests := []struct {
		name     string
		criteria []vulnerability.Criteria
		validate func(t *testing.T, builder *searchQueryBuilder)
	}{
		{
			name: "package name criteria",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-package"),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.NotNil(t, builder.query.pkgSpec)
				require.Equal(t, "test-package", builder.query.pkgSpec.Name)
			},
		},
		{
			name: "unaffected criteria",
			criteria: []vulnerability.Criteria{
				search.ForUnaffected(),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.True(t, builder.query.unaffectedOnly)
			},
		},
		{
			name: "ecosystem criteria with package type",
			criteria: []vulnerability.Criteria{
				search.ByEcosystem(syftPkg.Java, syftPkg.JavaPkg),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.NotNil(t, builder.query.pkgSpec)
				require.Equal(t, syftPkg.JavaPkg, builder.query.pkgType)
				require.Equal(t, "java-archive", builder.query.pkgSpec.Ecosystem)
			},
		},
		{
			name: "ID criteria",
			criteria: []vulnerability.Criteria{
				search.ByID("CVE-2021-1234"),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.Len(t, builder.query.vulnSpecs, 1)
				require.Equal(t, "CVE-2021-1234", builder.query.vulnSpecs[0].Name)
			},
		},
		{
			name: "CPE criteria",
			criteria: []vulnerability.Criteria{
				search.ByCPE(cpe.Must("cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*", "")),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.NotNil(t, builder.query.cpeSpec)
				require.Equal(t, "apache", builder.query.cpeSpec.Vendor)
				require.Equal(t, "tomcat", builder.query.cpeSpec.Product)
				require.NotNil(t, builder.query.pkgSpec)
				require.NotNil(t, builder.query.pkgSpec.CPE)
			},
		},
		{
			name: "distro criteria",
			criteria: []vulnerability.Criteria{
				search.ByDistro(*distro.New(distro.Ubuntu, "20.04", "")),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.Len(t, builder.query.osSpecs, 1)
				require.Equal(t, "ubuntu", builder.query.osSpecs[0].Name)
				require.Equal(t, "20", builder.query.osSpecs[0].MajorVersion)
			},
		},
		{
			name: "multiple criteria",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-package"),
				search.ForUnaffected(),
				search.ByID("CVE-2021-1234"),
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.NotNil(t, builder.query.pkgSpec)
				require.Equal(t, "test-package", builder.query.pkgSpec.Name)
				require.True(t, builder.query.unaffectedOnly)
				require.Len(t, builder.query.vulnSpecs, 1)
				require.Equal(t, "CVE-2021-1234", builder.query.vulnSpecs[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := newSearchQueryBuilder()
			err := builder.ApplyCriteria(tt.criteria)
			require.NoError(t, err)
			tt.validate(t, builder)
		})
	}
}

func TestQueryBuilder_CPEErrorHandling(t *testing.T) {
	builder := newSearchQueryBuilder()

	// create a CPE without a product (which should cause an error)
	invalidCPE := cpe.CPE{
		Attributes: cpe.Attributes{
			Part:   "a",
			Vendor: "vendor",
			// no product specified
		},
	}
	criteria := []vulnerability.Criteria{
		search.ByCPE(invalidCPE),
	}

	err := builder.ApplyCriteria(criteria)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must specify product to search by CPE")
}

func TestQueryBuilder_PostProcess(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*searchQueryBuilder)
		validate func(t *testing.T, builder *searchQueryBuilder)
	}{
		{
			name: "sets default OS when none specified",
			setup: func(builder *searchQueryBuilder) {
				// no OS specs set
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.Len(t, builder.query.osSpecs, 1)
				require.Equal(t, NoOSSpecified, builder.query.osSpecs[0])
			},
		},
		{
			name: "does not override existing OS specs",
			setup: func(builder *searchQueryBuilder) {
				builder.query.osSpecs = append(builder.query.osSpecs, &OSSpecifier{
					Name:         "ubuntu",
					MajorVersion: "20",
				})
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.Len(t, builder.query.osSpecs, 1)
				require.Equal(t, "ubuntu", builder.query.osSpecs[0].Name)
			},
		},
		{
			name: "normalizes package name when pkgType and pkgSpec are set",
			setup: func(builder *searchQueryBuilder) {
				builder.query.pkgType = syftPkg.GemPkg
				builder.query.pkgSpec = &PackageSpecifier{
					Name: "Test_Package",
				}
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				// verify that normalization was attempted (actual result may vary by package type)
				require.NotEmpty(t, builder.query.pkgSpec.Name)
			},
		},
		{
			name: "preserves remaining criteria that aren't processed",
			setup: func(builder *searchQueryBuilder) {
				// add some criteria that should remain
				builder.remainingCriteria = []vulnerability.Criteria{
					search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
						return true, "", nil
					}),
				}
			},
			validate: func(t *testing.T, builder *searchQueryBuilder) {
				require.Len(t, builder.remainingCriteria, 1, "func criteria should remain unprocessed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := newSearchQueryBuilder()
			tt.setup(builder)

			_, _, err := builder.Build()
			require.NoError(t, err)

			tt.validate(t, builder)
		})
	}
}

func TestQueryBuilder_Build(t *testing.T) {
	builder := newSearchQueryBuilder()

	// add some test data
	builder.query.unaffectedOnly = true
	builder.remainingCriteria = []vulnerability.Criteria{
		search.ByPackageName("some-remaining-criteria"),
	}

	query, remaining, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, query)
	require.True(t, query.unaffectedOnly)
	require.Len(t, remaining, 1)
}

func TestQueryBuilder_ExactDistroCriteria(t *testing.T) {
	tests := []struct {
		name     string
		criteria []vulnerability.Criteria
		validate func(t *testing.T, query *searchQuery, remaining []vulnerability.Criteria)
	}{
		{
			name: "exact distro criteria should be handled with DisableAliasing set",
			criteria: []vulnerability.Criteria{
				search.ByExactDistro(*distro.New(distro.AlmaLinux, "8", "")),
			},
			validate: func(t *testing.T, query *searchQuery, remaining []vulnerability.Criteria) {
				require.Len(t, query.osSpecs, 1)
				require.Equal(t, "almalinux", query.osSpecs[0].Name)
				require.Equal(t, "8", query.osSpecs[0].MajorVersion)
				require.True(t, query.osSpecs[0].DisableAliasing, "ExactDistroCriteria should set DisableAliasing=true")
				require.Empty(t, remaining, "ExactDistroCriteria should be handled, not left in remaining")
			},
		},
		{
			name: "exact distro criteria should not be left in remaining criteria",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("mariadb"),
				search.ByExactDistro(*distro.New(distro.AlmaLinux, "8", "")),
				search.ForUnaffected(),
			},
			validate: func(t *testing.T, query *searchQuery, remaining []vulnerability.Criteria) {
				require.NotNil(t, query.pkgSpec)
				require.Equal(t, "mariadb", query.pkgSpec.Name)
				require.Len(t, query.osSpecs, 1)
				require.Equal(t, "almalinux", query.osSpecs[0].Name)
				require.True(t, query.osSpecs[0].DisableAliasing, "ExactDistroCriteria should set DisableAliasing=true")
				require.True(t, query.unaffectedOnly)
				require.Empty(t, remaining, "ExactDistroCriteria should be handled, not left in remaining")
			},
		},
		{
			name: "regular distro criteria should not set DisableAliasing",
			criteria: []vulnerability.Criteria{
				search.ByDistro(*distro.New(distro.AlmaLinux, "8", "")),
			},
			validate: func(t *testing.T, query *searchQuery, remaining []vulnerability.Criteria) {
				require.Len(t, query.osSpecs, 1)
				require.Equal(t, "almalinux", query.osSpecs[0].Name)
				require.Equal(t, "8", query.osSpecs[0].MajorVersion)
				require.False(t, query.osSpecs[0].DisableAliasing, "Regular DistroCriteria should keep DisableAliasing=false")
				require.Empty(t, remaining)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, remaining, err := newSearchQuery(test.criteria)
			require.NoError(t, err)
			test.validate(t, query, remaining)
		})
	}
}

func TestQueryBuilder_IntegrationWithRealCriteria(t *testing.T) {
	// test the full flow that mimics parseCriteria behavior
	criteria := []vulnerability.Criteria{
		search.ByPackageName("log4j"),
		search.ByEcosystem(syftPkg.Java, syftPkg.JavaPkg),
		search.ByDistro(*distro.New(distro.Ubuntu, "20.04", "")),
		search.ByID("CVE-2021-44228"),
		search.ForUnaffected(),
		search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return true, "", nil
		}),
	}

	builder := newSearchQueryBuilder()

	err := builder.ApplyCriteria(criteria)
	require.NoError(t, err)

	query, remaining, err := builder.Build()
	require.NoError(t, err)

	// validate the built query
	require.NotNil(t, query.pkgSpec)
	require.Equal(t, "log4j", query.pkgSpec.Name)
	require.Equal(t, syftPkg.JavaPkg, query.pkgType)
	require.Len(t, query.osSpecs, 1)
	require.Equal(t, "ubuntu", query.osSpecs[0].Name)
	require.Len(t, query.vulnSpecs, 1)
	require.Equal(t, "CVE-2021-44228", query.vulnSpecs[0].Name)
	require.True(t, query.unaffectedOnly)

	// func criteria should remain unprocessed
	require.Len(t, remaining, 1)
}
