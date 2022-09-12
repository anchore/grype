package rpm

import (
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockProvider struct {
	data map[string]map[string][]vulnerability.Vulnerability
}

func newMockProvider(packageName, indirectName string, withEpoch bool, withPackageQualifiers bool) *mockProvider {
	pr := mockProvider{
		data: make(map[string]map[string][]vulnerability.Vulnerability),
	}
	if withEpoch {
		pr.stubWithEpoch(packageName, indirectName)
	} else if withPackageQualifiers {
		pr.stubWithPackageQualifiers(packageName)
	} else {
		pr.stub(packageName, indirectName)
	}

	return &pr
}

func (pr *mockProvider) stub(packageName, indirectName string) {
	pr.data["rhel:8"] = map[string][]vulnerability.Vulnerability{
		// direct...
		packageName: {
			{
				Constraint: version.MustGetConstraint("<= 7.1.3-6", version.RpmFormat),
				ID:         "CVE-2014-fake-1",
			},
		},
		// indirect...
		indirectName: {
			// expected...
			{
				Constraint: version.MustGetConstraint("< 7.1.4-5", version.RpmFormat),
				ID:         "CVE-2014-fake-2",
			},
			{
				Constraint: version.MustGetConstraint("< 8.0.2-0", version.RpmFormat),
				ID:         "CVE-2013-fake-3",
			},
			// unexpected...
			{
				Constraint: version.MustGetConstraint("< 7.0.4-1", version.RpmFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}
}

func (pr *mockProvider) stubWithEpoch(packageName, indirectName string) {
	pr.data["rhel:8"] = map[string][]vulnerability.Vulnerability{
		// direct...
		packageName: {
			{
				Constraint: version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
				ID:         "CVE-2021-1",
			},
			{
				Constraint: version.MustGetConstraint("<= 0:2.28-419.el8.", version.RpmFormat),
				ID:         "CVE-2021-2",
			},
		},
		// indirect...
		indirectName: {
			{
				Constraint: version.MustGetConstraint("< 5.28.3-420.el8", version.RpmFormat),
				ID:         "CVE-2021-3",
			},
			// unexpected...
			{
				Constraint: version.MustGetConstraint("< 4:5.26.3-419.el8", version.RpmFormat),
				ID:         "CVE-2021-4",
			},
		},
	}
}

func (pr *mockProvider) stubWithPackageQualifiers(packageName string) {
	pr.data["rhel:8"] = map[string][]vulnerability.Vulnerability{
		// direct...
		packageName: {
			{
				Constraint: version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
				ID:         "CVE-2021-1",
				PackageQualifiers: []qualifier.Qualifier{
					rpmmodularity.NewRpmModularityQualifier("containertools:3"),
				},
			},
			{
				Constraint: version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
				ID:         "CVE-2021-2",
				PackageQualifiers: []qualifier.Qualifier{
					rpmmodularity.NewRpmModularityQualifier(""),
				},
			},
			{
				Constraint: version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
				ID:         "CVE-2021-3",
			},
			{
				Constraint: version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
				ID:         "CVE-2021-4",
				PackageQualifiers: []qualifier.Qualifier{
					rpmmodularity.NewRpmModularityQualifier("containertools:4"),
				},
			},
		},
	}
}

func (pr *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	var ty = strings.ToLower(d.Type.String())
	if d.Type == distro.CentOS || d.Type == distro.RedHat || d.Type == distro.RockyLinux || d.Type == distro.AlmaLinux {
		ty = "rhel"
	}

	return pr.data[ty+":"+d.FullVersion()][p.Name], nil
}

func (pr *mockProvider) GetByCPE(request syftPkg.CPE) (v []vulnerability.Vulnerability, err error) {
	return v, err
}

func (pr *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) (v []vulnerability.Vulnerability, err error) {
	return v, err
}
