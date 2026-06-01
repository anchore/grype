package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestUbuntuTransform exercises the ubuntu strategy against real UBUNTU-CVE-*
// fixtures extracted from the on-disk vunnel cache.
//
// The contract being locked in here is the *dpkg matcher's* contract — not the
// alma/bitnami/rootio contract. The dpkg matcher already queries DB rows
// produced by the legacy OS-schema transformer for Ubuntu records today
// (grype/db/v6/build/transformers/os/transform.go); the ubuntu OSV strategy
// must produce rows fungible with those, so that the matcher cannot tell the
// difference between an OSV-sourced row and a legacy OS-sourced row:
//
//   - db.AffectedPackageHandle (AK semantic, matching os.Transform's
//     getPackages affected path — not the alma/rootio NAK path).
//   - Package.Ecosystem == "deb" (dpkg matcher gates on syftPkg.DebPkg).
//   - OperatingSystem with Name="ubuntu", ReleaseID="ubuntu", MajorVersion,
//     MinorVersion, and Codename populated from the codename lookup; Channel
//     populated for ESM/Pro releases.
//   - Range.Version.Type == "dpkg" (matches os.Transform's
//     fixedInEntry.VersionFormat for ubuntu records).
//   - Range.Version.Constraint == "< <fix>" when a fixed event exists, "" when
//     only {introduced:"0"} is present (mirroring the OS transformer's
//     enforceConstraint behavior for AffectedPackageHandle with empty fixed
//     version).
//   - Range.Fix.State == FixedStatus when fix version present;
//     NotFixedStatus when fix version absent. Detail.Available populated
//     from database_specific.anchore.fixes[] via the shared
//     extractFixAvailability helper.
//
// Each fixture targets a distinct shape:
//
//   - UBUNTU-CVE-2023-38545 (curl): dominant shape — fix events, multi-release
//     (Ubuntu:22.04:LTS + Ubuntu:24.04:LTS), mixed CVSS_V3 + Ubuntu vendor
//     severity, anchore fix-availability detail.
//   - UBUNTU-CVE-2006-20001 (apache2): Pro/ESM coverage — five affecteds
//     spanning Ubuntu:Pro:14.04:LTS (no fix), Ubuntu:Pro:16.04:LTS (with
//     +esm-suffixed fix), and three regular LTS releases. Locks in Channel
//     handling and the not-fixed Pro entry simultaneously.
//   - UBUNTU-CVE-2001-1593 (a2ps): withdrawn record. Locks in skip behavior.
//   - UBUNTU-CVE-2008-7320 (seahorse): withdrawn + schema-1.6.3 tail. Locks
//     in the skip behavior on the older schema variant.
func TestUbuntuTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "UBUNTU-CVE-2023-38545 (curl) — fix events, multi-release, mixed severity",
			fixturePath: "testdata/UBUNTU-CVE-2023-38545.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					// Name and BlobValue.ID are the upstream CVE — that's the
					// identifier users have always seen for Ubuntu records
					// in grype output. The OSV record id "UBUNTU-CVE-2023-38545"
					// is Canonical's internal key and is intentionally not
					// stored anywhere on the row.
					Name:          "CVE-2023-38545",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.April, 22, 7, 45, 24, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2023, time.October, 11, 6, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CVE-2023-38545",
						Description: "This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due to this bug, the local variable that means \"let the host resolve the name\" could get the wrong value during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target buffer instead of copying just the resolved address there. The target buffer being a heap based buffer, and the host name coming from the URL that curl has been told to operate with.",
						References: []db.Reference{
							{URL: "https://ubuntu.com/security/CVE-2023-38545", Tags: []string{"REPORT"}},
							{URL: "https://curl.se/docs/CVE-2023-38545.html", Tags: []string{"REPORT"}},
							{URL: "https://ubuntu.com/security/notices/USN-6429-1", Tags: []string{"ADVISORY"}},
							{URL: "https://ubuntu.com/security/notices/USN-6429-3", Tags: []string{"ADVISORY"}},
							{URL: "https://www.cve.org/CVERecord?id=CVE-2023-38545", Tags: []string{"REPORT"}},
						},
						// The first (and typically only) upstream CVE is promoted to Name
						// above; Aliases holds any *additional* upstreams. Most Ubuntu
						// OSV records carry a single upstream, so this is nil for the
						// dominant case. Mirrors the legacy OS transformer, whose
						// getAliases returns Metadata.CVE (empty for real ubuntu records).
						Aliases: nil,
						// Ubuntu vendor severity goes through the CHMLN scheme (lowercase
						// "high"/"medium"/"low"/"negligible"/"unknown") — same mapping the
						// legacy OS transformer uses for the vulnerability.Severity string,
						// so OSV-sourced and OS-sourced rows are indistinguishable downstream.
						// CHMLN comes first, then CVSS entries in source order; the legacy
						// transformer emits the same ordering.
						Severities: []db.Severity{
							{Scheme: db.SeveritySchemeCHMLN, Value: "high", Rank: 1},
							{Scheme: db.SeveritySchemeCVSS, Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.1",
							}, Rank: 2},
							{Scheme: db.SeveritySchemeCVSS, Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
								Version: "3.1",
							}, Rank: 2},
						},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "curl",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "22",
							MinorVersion: "04",
							Codename:     "jammy",
						},
						BlobValue: &db.PackageBlob{
							// Single-upstream case → no "extra" CVEs to surface; the
							// upstream is already the row's primary Name. Mirrors
							// legacy ubuntu PackageBlob.CVEs (which is empty since
							// Metadata.CVE is empty on those records).
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "< 7.81.0-1ubuntu1.14",
								},
								Fix: &db.Fix{
									Version: "7.81.0-1ubuntu1.14",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2023, time.October, 11, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "curl",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "24",
							MinorVersion: "04",
							Codename:     "noble",
						},
						BlobValue: &db.PackageBlob{
							// Single-upstream case → no "extra" CVEs to surface; the
							// upstream is already the row's primary Name. Mirrors
							// legacy ubuntu PackageBlob.CVEs (which is empty since
							// Metadata.CVE is empty on those records).
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "< 8.2.1-1ubuntu3.1",
								},
								Fix: &db.Fix{
									Version: "8.2.1-1ubuntu3.1",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2023, time.October, 11, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "UBUNTU-CVE-2006-20001 (apache2) — Pro/ESM mix, no-fix Pro entry, +esm fix suffix",
			fixturePath: "testdata/UBUNTU-CVE-2006-20001.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CVE-2006-20001",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.April, 22, 7, 37, 33, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2023, time.January, 17, 20, 15, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CVE-2006-20001",
						Description: "A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool (heap) memory location beyond the header value sent. This could cause the process to crash. This issue affects Apache HTTP Server 2.4.54 and earlier.",
						References: []db.Reference{
							{URL: "https://ubuntu.com/security/CVE-2006-20001", Tags: []string{"REPORT"}},
							{URL: "https://www.openwall.com/lists/oss-security/2023/01/17/5", Tags: []string{"REPORT"}},
							{URL: "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2006-20001", Tags: []string{"REPORT"}},
							{URL: "https://httpd.apache.org/security/vulnerabilities_24.html", Tags: []string{"REPORT"}},
							{URL: "https://ubuntu.com/security/notices/USN-5834-1", Tags: []string{"ADVISORY"}},
							{URL: "https://ubuntu.com/security/notices/USN-5839-1", Tags: []string{"ADVISORY"}},
							{URL: "https://www.cve.org/CVERecord?id=CVE-2006-20001", Tags: []string{"REPORT"}},
						},
						Aliases: nil,
						Severities: []db.Severity{
							{Scheme: db.SeveritySchemeCHMLN, Value: "medium", Rank: 1},
							{Scheme: db.SeveritySchemeCVSS, Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								Version: "3.1",
							}, Rank: 2},
						},
					},
				},
				Related: affectedPkgSlice(
					// Sort is by package name, then ecosystem, then constraint. All five
					// entries share Name="apache2" and Ecosystem="deb"; constraint then
					// tiebreaks: "" < "< 2.4.18-..." < "< 2.4.29-..." < "< 2.4.41-..." <
					// "< 2.4.52-...". That puts Pro:14.04 (no fix, empty constraint) first
					// and the rest in ascending fix-version order.
					db.AffectedPackageHandle{
						// Pro:14.04 — no fix shipped. Empty constraint + NotFixedStatus
						// matches the legacy OS transformer's behavior for an
						// AffectedPackageHandle whose FixedIn.Version cleans to empty.
						Package: &db.Package{
							Name:      "apache2",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "14",
							MinorVersion: "04",
							Codename:     "trusty",
							// Channel="esm" locks in the canonical name for Ubuntu Pro/ESM
							// fix data — mirrors the existing FixChannel convention
							// (distro.FixChannel.Name for RHEL EUS is "eus", per the
							// short-channel-name pattern). This is a fresh design decision;
							// no existing legacy data carried a channel, so this test pins
							// the contract.
							Channel: "esm",
						},
						BlobValue: &db.PackageBlob{
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "",
								},
								Fix: &db.Fix{
									State: db.NotFixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						// Pro:16.04 — fix shipped with +esm suffix. The Pro tier means
						// Channel="esm"; the version string itself is opaque to the
						// strategy.
						Package: &db.Package{
							Name:      "apache2",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "16",
							MinorVersion: "04",
							Codename:     "xenial",
							Channel:      "esm",
						},
						BlobValue: &db.PackageBlob{
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "< 2.4.18-2ubuntu3.17+esm8",
								},
								Fix: &db.Fix{
									Version: "2.4.18-2ubuntu3.17+esm8",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2023, time.January, 17, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "apache2",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "18",
							MinorVersion: "04",
							Codename:     "bionic",
						},
						BlobValue: &db.PackageBlob{
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "< 2.4.29-1ubuntu4.26",
								},
								Fix: &db.Fix{
									Version: "2.4.29-1ubuntu4.26",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2023, time.January, 17, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "apache2",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "20",
							MinorVersion: "04",
							Codename:     "focal",
						},
						BlobValue: &db.PackageBlob{
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "< 2.4.41-4ubuntu3.13",
								},
								Fix: &db.Fix{
									Version: "2.4.41-4ubuntu3.13",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2023, time.January, 17, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "apache2",
							Ecosystem: "deb",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "ubuntu",
							ReleaseID:    "ubuntu",
							MajorVersion: "22",
							MinorVersion: "04",
							Codename:     "jammy",
						},
						BlobValue: &db.PackageBlob{
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "dpkg",
									Constraint: "< 2.4.52-1ubuntu4.3",
								},
								Fix: &db.Fix{
									Version: "2.4.52-1ubuntu4.3",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2023, time.January, 17, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
										},
									},
								},
							}},
						},
					},
				),
			}},
		},
		{
			// Withdrawn records are skipped entirely. Canonical retracted the CVE
			// for this release; there's nothing to emit. Mirrors the alma/bitnami
			// approach of "no entries" rather than "emit with Status=Rejected" —
			// downstream consumers don't have to filter, and a future user
			// scanning an EOL image against a CVE Canonical retracted won't get a
			// stale hit. The legacy OS-schema record (if any survives in the
			// legacy/ passthrough for this CVE) is emitted unchanged and is the
			// only path a withdrawn-by-OSV CVE can still reach the DB.
			name:        "UBUNTU-CVE-2001-1593 (a2ps) — withdrawn, skipped",
			fixturePath: "testdata/UBUNTU-CVE-2001-1593.json",
			want:        nil,
		},
		{
			// Same skip path on the older schema variant; this fixture also lacks
			// an `upstream` field (so a non-skipped path would need to handle
			// nil-aliases too).
			name:        "UBUNTU-CVE-2008-7320 (seahorse) — withdrawn + schema-1.6.3, skipped",
			fixturePath: "testdata/UBUNTU-CVE-2008-7320.json",
			want:        nil,
		},
	}
	runTransformCases(t, tests)
}

// TestUbuntuStrategyMatches locks in the dispatch envelope — every ID that
// the strategy claims, and (critically) every ID shape it must NOT claim. The
// strategy registry is order-sensitive (first Matches wins), so a strategy
// that over-claims could silently steal records from another provider. The
// negative cases below catch:
//
//   - ALSA-/ALBA-/ALEA- (alma's territory)
//   - BIT-               (bitnami)
//   - ROOT-              (root.io)
//   - USN-               (USN ingestion is deferred; the records exist in
//     osv/usn/ but no strategy should be picking them up today)
//   - GHSA-/CVE- generic OSV IDs (unscoped — should fall through to default
//     skip with a warning, not be hijacked by ubuntu)
//   - lowercased "ubuntu-cve-..." (vunnel writes the identifier lowercased
//     when keying its results.db, but the OSV record's `id` field is
//     uppercase. Matches() must gate on the uppercase form because Transform
//     is invoked with the raw OSV record. Lowercase here would indicate the
//     wrong shape was handed in.)
func TestUbuntuStrategyMatches(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{id: "UBUNTU-CVE-2023-38545", want: true},
		{id: "UBUNTU-CVE-2001-1593", want: true},
		// year boundary — still UBUNTU-CVE-, still claimed
		{id: "UBUNTU-CVE-2026-0001", want: true},

		// negative — other OSV providers
		{id: "ALSA-2020:1636", want: false},
		{id: "ALBA-2024:0001", want: false},
		{id: "ALEA-2024:0001", want: false},
		{id: "BIT-apache-2020-11984", want: false},
		{id: "ROOT-OS-UBUNTU-2204-CVE-2025-68973", want: false},

		// USN parsing is deferred — strategy should not claim USN records.
		{id: "USN-6429-1", want: false},
		{id: "USN-5834-1", want: false},

		// generic / unscoped OSV IDs
		{id: "GHSA-xxxx-yyyy-zzzz", want: false},
		{id: "CVE-2023-38545", want: false},

		// shape sentinels
		{id: "", want: false},
		{id: "ubuntu-cve-2023-38545", want: false}, // lowercase: matcher input is the OSV record's uppercase ID
		{id: "UBUNTU-USN-6429-1", want: false},     // hypothetical USN-flavored ubuntu ID — still not ours
		{id: "UBUNTU-CVE", want: false},            // prefix-only, no actual CVE id
	}
	s := ubuntuStrategy{}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := s.Matches(tt.id); got != tt.want {
				t.Errorf("ubuntuStrategy.Matches(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

// TestUbuntuOSFromEcosystem locks in the ecosystem-string parser. Real records
// emit three shapes:
//
//   - "Ubuntu:22.04:LTS" — 3-segment, LTS suffix is decorative.
//   - "Ubuntu:25.10"     — 2-segment, interim release.
//   - "Ubuntu:Pro:14.04:LTS" — 4-segment, Pro/ESM channel.
//
// The dpkg matcher's search.ByDistro criteria gates on (Name, MajorVersion,
// MinorVersion, Channel), so all four must land correctly for the matcher to
// resolve queries against these OS rows. Codename is populated via the same
// codename lookup the legacy transformer uses (`codename.LookupOS`); rows
// without a codename in the table get an empty Codename rather than failing.
func TestUbuntuOSFromEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      *db.OperatingSystem
	}{
		{
			name:      "standard LTS 3-segment",
			ecosystem: "Ubuntu:22.04:LTS",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "22",
				MinorVersion: "04",
				Codename:     "jammy",
			},
		},
		{
			name:      "trusty (oldest covered LTS)",
			ecosystem: "Ubuntu:14.04:LTS",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "14",
				MinorVersion: "04",
				Codename:     "trusty",
			},
		},
		{
			name:      "noble (current LTS)",
			ecosystem: "Ubuntu:24.04:LTS",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "24",
				MinorVersion: "04",
				Codename:     "noble",
			},
		},
		{
			name:      "interim 2-segment (no :LTS)",
			ecosystem: "Ubuntu:25.10",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "25",
				MinorVersion: "10",
				Codename:     "questing",
			},
		},
		{
			name:      "Pro 4-segment with :LTS",
			ecosystem: "Ubuntu:Pro:14.04:LTS",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "14",
				MinorVersion: "04",
				Codename:     "trusty",
				Channel:      "esm",
			},
		},
		{
			name:      "Pro 4-segment, current LTS",
			ecosystem: "Ubuntu:Pro:22.04:LTS",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "22",
				MinorVersion: "04",
				Codename:     "jammy",
				Channel:      "esm",
			},
		},

		// --- negative cases ---
		//
		// The strategy is the only caller of this function, and it discards
		// the affected entry on nil return. We want every malformed input to
		// produce nil rather than a partially-populated OperatingSystem the
		// matcher would then half-resolve.
		{
			name:      "empty string",
			ecosystem: "",
			want:      nil,
		},
		{
			name:      "single segment, no version",
			ecosystem: "Ubuntu",
			want:      nil,
		},
		{
			name:      "wrong distro",
			ecosystem: "Debian:11",
			want:      nil,
		},
		{
			name:      "non-numeric version major",
			ecosystem: "Ubuntu:focal",
			want:      nil,
		},
		{
			name:      "Pro with no version",
			ecosystem: "Ubuntu:Pro",
			want:      nil,
		},
		{
			name:      "Pro with non-numeric version",
			ecosystem: "Ubuntu:Pro:jammy:LTS",
			want:      nil,
		},
		{
			name:      "lowercase 'ubuntu' (case-insensitive distro match)",
			ecosystem: "ubuntu:22.04:LTS",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "22",
				MinorVersion: "04",
				Codename:     "jammy",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ubuntuOSFromEcosystem(tt.ecosystem)
			if got == nil || tt.want == nil {
				if got != tt.want {
					t.Errorf("ubuntuOSFromEcosystem(%q) = %v, want %v", tt.ecosystem, got, tt.want)
				}
				return
			}
			if *got != *tt.want {
				t.Errorf("ubuntuOSFromEcosystem(%q):\n  got:  %+v\n  want: %+v", tt.ecosystem, *got, *tt.want)
			}
		})
	}
}

// TestUbuntuRangesFromAffected locks in the range-shape decisions independent
// of any specific fixture. The shared getGrypeRangesFromRange helper already
// handles introduced/fixed pairs correctly (alma/bitnami/rootio share it), but
// it returns an empty slice when an affected entry only carries
// {introduced:"0"} with no fixed event. The legacy OS transformer's
// AffectedPackageHandle path produces an empty-constraint range with
// NotFixedStatus for that condition (FixedIn with empty Version), so the
// ubuntu OSV strategy needs to do the same — otherwise the dpkg matcher will
// see a hole where Canonical says "we acknowledge this CVE but no fix has
// shipped." `ubuntuRangesFromAffected` wraps the shared helper and adds that
// sentinel.
func TestUbuntuRangesFromAffected(t *testing.T) {
	tests := []struct {
		name     string
		affected osvmodel.Affected
		want     []db.Range
	}{
		{
			name: "introduced=0 + fixed produces < fix range with FixedStatus and fix availability",
			affected: osvmodel.Affected{
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
						{Fixed: "7.81.0-1ubuntu1.14"},
					},
					DatabaseSpecific: map[string]any{
						"anchore": map[string]any{
							"fixes": []any{
								map[string]any{
									"version": "7.81.0-1ubuntu1.14",
									"date":    "2023-10-11",
									"kind":    "advisory",
								},
							},
						},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: "< 7.81.0-1ubuntu1.14"},
				Fix: &db.Fix{
					Version: "7.81.0-1ubuntu1.14",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: timeRef(time.Date(2023, time.October, 11, 0, 0, 0, 0, time.UTC)),
							Kind: "advisory",
						},
					},
				},
			}},
		},
		{
			name: "bare introduced=0 produces empty-constraint range with NotFixedStatus",
			affected: osvmodel.Affected{
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: ""},
				Fix:     &db.Fix{State: db.NotFixedStatus},
			}},
		},
		{
			name: "fix with +esm suffix preserved verbatim",
			affected: osvmodel.Affected{
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
						{Fixed: "2.4.18-2ubuntu3.17+esm8"},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: "< 2.4.18-2ubuntu3.17+esm8"},
				Fix: &db.Fix{
					Version: "2.4.18-2ubuntu3.17+esm8",
					State:   db.FixedStatus,
				},
			}},
		},
		{
			// vunnel stamps database_specific.anchore.status = "wont-fix" onto sliced
			// records whose (cve, distro, source-pkg) tuple is marked won't-fix in
			// Canonical's OpenVEX feed. The no-fix sentinel range we emit here must
			// honor that signal — otherwise this is the user-visible regression vs.
			// the v3 OS-schema path (which used VendorAdvisory.NoAdvisory:true →
			// WontFixStatus for the same semantic).
			name: "bare introduced=0 with vex wont-fix annotation produces WontFixStatus sentinel",
			affected: osvmodel.Affected{
				DatabaseSpecific: map[string]any{
					"anchore": map[string]any{
						"status": "wont-fix",
					},
				},
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: ""},
				Fix:     &db.Fix{State: db.WontFixStatus},
			}},
		},
		{
			// status set but not "wont-fix" → fall back to NotFixedStatus. Forward-compatible
			// with any future status values vunnel might emit.
			name: "bare introduced=0 with unrecognized anchore.status falls back to NotFixedStatus",
			affected: osvmodel.Affected{
				DatabaseSpecific: map[string]any{
					"anchore": map[string]any{
						"status": "some-future-value",
					},
				},
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: ""},
				Fix:     &db.Fix{State: db.NotFixedStatus},
			}},
		},
		{
			// anchore key present but no status sub-key → NotFixedStatus.
			name: "bare introduced=0 with anchore but no status key falls back to NotFixedStatus",
			affected: osvmodel.Affected{
				DatabaseSpecific: map[string]any{
					"anchore": map[string]any{
						"fixes": []any{},
					},
				},
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: ""},
				Fix:     &db.Fix{State: db.NotFixedStatus},
			}},
		},
		{
			// wont-fix annotation is ignored when there IS a fixed event — the shared
			// helper produces the FixedStatus range and the no-fix sentinel doesn't fire.
			// Forward-protects against a confusing combination (annotation says wont-fix
			// but Canonical also published a fix on the same release).
			name: "wont-fix annotation ignored when a fixed event is present",
			affected: osvmodel.Affected{
				DatabaseSpecific: map[string]any{
					"anchore": map[string]any{
						"status": "wont-fix",
					},
				},
				Ranges: []osvmodel.Range{{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
						{Fixed: "1.2.3-0ubuntu1"},
					},
				}},
			},
			want: []db.Range{{
				Version: db.Version{Type: "dpkg", Constraint: "< 1.2.3-0ubuntu1"},
				Fix: &db.Fix{
					Version: "1.2.3-0ubuntu1",
					State:   db.FixedStatus,
				},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ubuntuRangesFromAffected(tt.affected)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ubuntuRangesFromAffected:\n  got:  %+v\n  want: %+v", got, tt.want)
			}
		})
	}
}
