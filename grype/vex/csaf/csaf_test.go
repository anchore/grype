package csaf

import (
	"reflect"
	"testing"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
)

func Test_advisoryMatch_statement(t *testing.T) {
	type fields struct {
		Vulnerability *csaf.Vulnerability
		ProductID     csaf.ProductID
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "no vulnerability",
			fields: fields{
				Vulnerability: nil,
				ProductID:     "SPB-00260",
			},
			want: "",
		},
		{
			name: "no flags or threats",
			fields: fields{
				Vulnerability: &csaf.Vulnerability{
					CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
				},
				ProductID: "SPB-00260",
			},
			want: "",
		},
		{
			name: "flag with label",
			fields: fields{
				Vulnerability: &csaf.Vulnerability{
					CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
					Flags: []*csaf.Flag{{
						ProductIds: &csaf.Products{&[]csaf.ProductID{"SPB-00260"}[0]},
						Label:      &[]csaf.FlagLabel{"vulnerable_code_not_present"}[0],
					}},
				},
				ProductID: "SPB-00260",
			},
			want: "vulnerable_code_not_present",
		},
		{
			name: "flag with label, different product ID",
			fields: fields{
				Vulnerability: &csaf.Vulnerability{
					CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
					Flags: []*csaf.Flag{{
						ProductIds: &csaf.Products{&[]csaf.ProductID{"SPB-00260"}[0]},
						Label:      &[]csaf.FlagLabel{"vulnerable_code_not_present"}[0],
					}},
				},
				ProductID: "SPB-00261",
			},
			want: "",
		},
		{
			name: "threat with details",
			fields: fields{
				Vulnerability: &csaf.Vulnerability{
					CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
					Threats: []*csaf.Threat{{
						Category:   &[]csaf.ThreatCategory{csaf.CSAFThreatCategoryImpact}[0],
						Details:    &[]string{"Class with vulnerable code was removed before shipping"}[0],
						ProductIds: &csaf.Products{&[]csaf.ProductID{"SPB-00260"}[0]},
					}},
				},
				ProductID: "SPB-00260",
			},
			want: "Class with vulnerable code was removed before shipping",
		},
		{
			name: "threat with details, different product ID",
			fields: fields{
				Vulnerability: &csaf.Vulnerability{
					CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
					Threats: []*csaf.Threat{{
						Category:   &[]csaf.ThreatCategory{csaf.CSAFThreatCategoryImpact}[0],
						Details:    &[]string{"Class with vulnerable code was removed before shipping"}[0],
						ProductIds: &csaf.Products{&[]csaf.ProductID{"SPB-00260"}[0]},
					}},
				},
				ProductID: "SPB-00261",
			},
			want: "",
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			m := &advisoryMatch{
				Vulnerability: test.fields.Vulnerability,
				ProductID:     test.fields.ProductID,
			}
			if got := m.statement(); got != test.want {
				tt.Errorf("advisoryMatch.statement() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_advisories_matches(t *testing.T) {
	sampleAdv := &csaf.Advisory{
		ProductTree: &csaf.ProductTree{
			Branches: csaf.Branches{
				&[]csaf.Branch{{
					Branches: csaf.Branches{
						&[]csaf.Branch{{
							Category: &[]csaf.BranchCategory{csaf.CSAFBranchCategoryProductVersion}[0],
							Name:     &[]string{"2.6.0"}[0],
							Product: &csaf.FullProductName{
								Name:      &[]string{"Spring Boot 2.6.0"}[0],
								ProductID: &[]csaf.ProductID{"SPB-00260"}[0],
								ProductIdentificationHelper: &[]csaf.ProductIdentificationHelper{{
									PURL: &[]csaf.PURL{"pkg:apk/alpine/libssl3@3.0.8-r3"}[0],
								}}[0],
							},
						}}[0],
					},
					Category: &[]csaf.BranchCategory{csaf.CSAFBranchCategoryProductName}[0],
					Name:     &[]string{"Spring"}[0],
				}}[0],
			},
		},
		Vulnerabilities: []*csaf.Vulnerability{{
			CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
			ProductStatus: &[]csaf.ProductStatus{{
				KnownNotAffected: &csaf.Products{
					&[]csaf.ProductID{"SPB-00260"}[0],
				},
			}}[0],
		}},
	}

	type args struct {
		vulnID string
		purl   string
	}
	tests := []struct {
		name       string
		advisories advisories
		args       args
		want       *advisoryMatch
	}{
		{
			name:       "no advisories",
			advisories: advisories{},
			args:       args{vulnID: "CVE-1234-5678", purl: "pkg:apk/alpine/libssl3@3.0.8-r3"},
			want:       nil,
		},
		{
			name:       "no matching advisory",
			advisories: advisories{sampleAdv},
			args:       args{vulnID: "CVE-1234-5678", purl: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
			want:       nil,
		},
		{
			name:       "advisory matches vulnerability for given pURL",
			advisories: advisories{sampleAdv},
			args:       args{vulnID: "CVE-1234-5678", purl: "pkg:apk/alpine/libssl3@3.0.8-r3"},
			want: &advisoryMatch{
				Vulnerability: &csaf.Vulnerability{
					CVE: &[]csaf.CVE{"CVE-1234-5678"}[0],
					ProductStatus: &[]csaf.ProductStatus{{
						KnownNotAffected: &csaf.Products{
							&[]csaf.ProductID{"SPB-00260"}[0],
						},
					}}[0],
				},
				ProductID: "SPB-00260",
				Status:    knownNotAffected,
			},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			if got := test.advisories.matches(test.args.vulnID, test.args.purl); !reflect.DeepEqual(got, test.want) {
				tt.Errorf("advisories.matches() = %v, want %v", got, test.want)
			}
		})
	}
}
