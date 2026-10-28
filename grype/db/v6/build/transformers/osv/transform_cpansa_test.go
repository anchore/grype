package osv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/name"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func cpanFix(version string, date time.Time) *db.Fix {
	return &db.Fix{
		Version: version,
		State:   db.FixedStatus,
		Detail: &db.FixDetail{
			Available: &db.FixAvailability{
				Date: timeRef(date),
				Kind: "advisory",
			},
		},
	}
}

// TestCpansaTransform exercises the CPANSA strategy end-to-end against real
// records emitted by vunnel's cpan provider.
//
//   - CPANSA-Mojolicious-2022-03: no CVE alias at all. The advisory is only ever
//     reachable under its CPANSA id, so a pipeline that keys on CVEs loses it.
//   - CPANSA-DBD-SQLite-2018-8740-sqlite: upstream collapses dozens of separate
//     version windows under one id. They arrive as one affected entry with three
//     windows and three fix dates, and must stay one advisory. Also carries
//     underscore alpha versions (1.47_04), which are ordinary CPAN versions and
//     must not be mangled into semver pre-releases.
//   - CPANSA-ExtUtils-ParseXS-2016-1238: one id spanning two distributions, one
//     of which is the perl interpreter itself. Both names are used verbatim.
//   - CPANSA-libwww-perl-1995-01 with its affected list emptied by hand: an
//     advisory whose ranges resolved to nothing must produce no entries at all.
func TestCpansaTransform(t *testing.T) {
	fixDate2016 := time.Date(2016, time.August, 2, 0, 0, 0, 0, time.UTC)

	tests := []transformCase{
		{
			name:        "no CVE alias",
			fixturePath: "testdata/CPANSA-Mojolicious-2022-03.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CPANSA-Mojolicious-2022-03",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.July, 26, 6, 23, 50, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2022, time.December, 10, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CPANSA-Mojolicious-2022-03",
						Description: "Mojo::DOM did not correctly parse <script> tags.",
						References: []db.Reference{{
							URL:  "https://github.com/mojolicious/mojo/commit/6f195d85db6756022d3599f7d2634975688c9550",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://github.com/mojolicious/mojo/issues/2014",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://github.com/mojolicious/mojo/issues/2015",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{},
					},
				},
				Related: affectedPkgSlice(db.AffectedPackageHandle{
					Package: &db.Package{Name: "Mojolicious", Ecosystem: "cpan"},
					BlobValue: &db.PackageBlob{
						CVEs: []string{},
						Ranges: []db.Range{{
							Version: db.Version{Type: "cpan", Constraint: "< 9.31"},
							Fix:     cpanFix("9.31", time.Date(2022, time.December, 10, 0, 0, 0, 0, time.UTC)),
						}},
					},
				}),
			}},
		},
		{
			name:        "many entries collapsed under one id",
			fixturePath: "testdata/CPANSA-DBD-SQLite-2018-8740-sqlite.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CPANSA-DBD-SQLite-2018-8740-sqlite",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.July, 26, 6, 23, 50, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2018, time.March, 17, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CPANSA-DBD-SQLite-2018-8740-sqlite",
						Description: "In SQLite through 3.22.0, databases whose schema is corrupted using a CREATE TABLE AS statement could cause a NULL pointer dereference, related to build.c and prepare.c.",
						References:  dbdSQLiteReferences(),
						Aliases:     []string{"CVE-2018-8740"},
					},
				},
				Related: affectedPkgSlice(db.AffectedPackageHandle{
					Package: &db.Package{Name: "DBD-SQLite", Ecosystem: "cpan"},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2018-8740"},
						Ranges: []db.Range{{
							Version: db.Version{Type: "cpan", Constraint: ">= 1.00, < 1.35"},
							Fix:     cpanFix("1.35", time.Date(2018, time.March, 17, 0, 0, 0, 0, time.UTC)),
						}, {
							Version: db.Version{Type: "cpan", Constraint: ">= 1.36_01, < 1.47_04"},
							Fix:     cpanFix("1.47_04", time.Date(2018, time.March, 17, 0, 0, 0, 0, time.UTC)),
						}, {
							Version: db.Version{Type: "cpan", Constraint: ">= 1.47_05, < 1.59_01"},
							Fix:     cpanFix("1.59_01", time.Date(2018, time.March, 17, 0, 0, 0, 0, time.UTC)),
						}},
					},
				}),
			}},
		},
		{
			name:        "one id spanning two distributions, including the interpreter",
			fixturePath: "testdata/CPANSA-ExtUtils-ParseXS-2016-1238.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CPANSA-ExtUtils-ParseXS-2016-1238",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.July, 26, 6, 23, 50, 0, time.UTC)),
					PublishedDate: timeRef(fixDate2016),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CPANSA-ExtUtils-ParseXS-2016-1238",
						Description: extUtilsParseXSDescription,
						References:  extUtilsParseXSReferences(),
						Aliases:     []string{"CVE-2016-1238"},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{Name: "ExtUtils-ParseXS", Ecosystem: "cpan"},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2016-1238"},
							Ranges: []db.Range{{
								Version: db.Version{Type: "cpan", Constraint: "< 3.35"},
								Fix:     cpanFix("3.35", fixDate2016),
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{Name: "perl", Ecosystem: "cpan"},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2016-1238"},
							Ranges: []db.Range{{
								Version: db.Version{Type: "cpan", Constraint: "< 5.024001"},
								Fix:     cpanFix("5.024001", fixDate2016),
							}},
						},
					},
				),
			}},
		},
		{
			name:        "advisory with no affected packages is not emitted",
			fixturePath: "testdata/CPANSA-libwww-perl-1995-01-no-affected.json",
			want:        nil,
		},
		{
			// the shape upstream actually produces: an affected entry is present but its
			// ranges resolved to nothing, because the advisory predates any release CPANSA
			// records. Emitting it would write an empty constraint, and an empty constraint is
			// satisfied by every version, so this would report against every install.
			name:        "affected package whose ranges resolved to nothing is not emitted",
			fixturePath: "testdata/CPANSA-libwww-perl-1995-01-empty-ranges.json",
			want:        nil,
		},
	}

	runTransformCases(t, tests)
}

// TestCpansaPackageNameIsVerbatim guards the case-sensitivity requirement: CPAN
// distribution names are case sensitive, CPANSA keys match CPAN casing exactly,
// and no resolver may be registered for the cpan type that would fold case.
func TestCpansaPackageNameIsVerbatim(t *testing.T) {
	for _, n := range []string{"JSON-MaybeXS", "libwww-perl", "perl", "CPAN-02Packages-Search"} {
		p := cpansaPackage(osvmodel.Package{Ecosystem: "CPAN", Name: n})
		assert.Equal(t, n, p.Name)
		assert.Equal(t, "cpan", p.Ecosystem)
	}

	assert.Nil(t, name.FromType(syftPkg.Type("cpan")), "no name resolver may be registered for cpan")
}

const extUtilsParseXSDescription = "(1) cpan/Archive-Tar/bin/ptar, (2) cpan/Archive-Tar/bin/ptardiff, (3) cpan/Archive-Tar/bin/ptargrep, (4) cpan/CPAN/scripts/cpan, (5) cpan/Digest-SHA/shasum, (6) cpan/Encode/bin/enc2xs, (7) cpan/Encode/bin/encguess, (8) cpan/Encode/bin/piconv, (9) cpan/Encode/bin/ucmlint, (10) cpan/Encode/bin/unidump, (11) cpan/ExtUtils-MakeMaker/bin/instmodsh, (12) cpan/IO-Compress/bin/zipdetails, (13) cpan/JSON-PP/bin/json_pp, (14) cpan/Test-Harness/bin/prove, (15) dist/ExtUtils-ParseXS/lib/ExtUtils/xsubpp, (16) dist/Module-CoreList/corelist, (17) ext/Pod-Html/bin/pod2html, (18) utils/c2ph.PL, (19) utils/h2ph.PL, (20) utils/h2xs.PL, (21) utils/libnetcfg.PL, (22) utils/perlbug.PL, (23) utils/perldoc.PL, (24) utils/perlivp.PL, and (25) utils/splain.PL in Perl 5.x before 5.22.3-RC2 and 5.24 before 5.24.1-RC2 do not properly remove . (period) characters from the end of the includes directory array, which might allow local users to gain privileges via a Trojan horse module under the current working directory."

func webRefs(urls ...string) []db.Reference {
	refs := make([]db.Reference, 0, len(urls))
	for _, u := range urls {
		refs = append(refs, db.Reference{URL: u, Tags: []string{"WEB"}})
	}
	return refs
}

func dbdSQLiteReferences() []db.Reference {
	return webRefs(
		"https://www.sqlite.org/cgi/src/timeline?r=corrupt-schema",
		"https://bugs.launchpad.net/ubuntu/+source/sqlite3/+bug/1756349",
		"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=6964",
		"https://www.sqlite.org/cgi/src/vdiff?from=1774f1c3baf0bc3d&to=d75e67654aa9620b",
		"http://www.securityfocus.com/bid/103466",
		"https://lists.debian.org/debian-lts-announce/2019/01/msg00009.html",
		"http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00050.html",
		"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PU4NZ6DDU4BEM3ACM3FM6GLEPX56ZQXK/",
		"https://usn.ubuntu.com/4205-1/",
		"https://usn.ubuntu.com/4394-1/",
		"https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html",
		"https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
		"https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
	)
}

func extUtilsParseXSReferences() []db.Reference {
	return webRefs(
		"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00002.html",
		"http://perl5.git.perl.org/perl.git/commit/cee96d52c39b1e7b36e1c62d38bcd8d86e9a41ab",
		"http://www.debian.org/security/2016/dsa-3628",
		"http://www.nntp.perl.org/group/perl.perl5.porters/2016/07/msg238271.html",
		"http://www.securityfocus.com/bid/92136",
		"http://www.securitytracker.com/id/1036440",
		"https://h20566.www2.hpe.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c05240731",
		"https://lists.apache.org/thread.html/7f6a16bc0fd0fd5e67c7fd95bd655069a2ac7d1f88e42d3c853e601c%40%3Cannounce.apache.org%3E",
		"https://lists.debian.org/debian-lts-announce/2018/11/msg00016.html",
		"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2FBQOCV3GBAN2EYZUM3CFDJ4ECA3GZOK/",
		"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DOFRQWJRP2NQJEYEWOMECVW3HAMD5SYN/",
		"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TZBNQH3DMI7HDELJAZ4TFJJANHXOEDWH/",
		"https://rt.perl.org/Public/Bug/Display.html?id=127834",
		"https://security.gentoo.org/glsa/201701-75",
		"https://security.gentoo.org/glsa/201812-07",
		"https://perldoc.perl.org/5.24.1/perldelta",
	)
}
