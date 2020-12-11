package pkg

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/distro"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/syft/pkg"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestParseSyftJSON(t *testing.T) {
	tests := []struct {
		Fixture  string
		Packages []Package
		Context  Context
	}{
		{
			Fixture: "test-fixtures/syft-alpine.json",
			Packages: []Package{
				{
					id:      0,
					Name:    "alpine-baselayout",
					Version: "3.2.0-r6",
					Locations: []source.Location{
						{
							Path:         "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						},
					},
					Language: "",
					Licenses: []string{
						"GPL-2.0-only",
					},
					Type: "rpm",
					CPEs: []pkg.CPE{
						must(pkg.NewCPE("cpe:2.3:a:*:alpine-baselayout:3.2.0-r6:*:*:*:*:*:*:*")),
						must(pkg.NewCPE("cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r6:*:*:*:*:*:*:*")),
					},
					PURL:     "pkg:alpine/alpine-baselayout@3.2.0-r6?arch=x86_64",
					Metadata: RpmdbMetadata{SourceRpm: "a-source.srpm"},
				},
				{
					id:      1,
					Name:    "fake",
					Version: "1.2.0-r0",
					Locations: []source.Location{
						{
							Path:         "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						},
					},
					Language: "lang",
					Licenses: []string{
						"LGPL-3.0-or-later",
					},
					Type: "dpkg",
					CPEs: []pkg.CPE{
						must(pkg.NewCPE("cpe:2.3:a:*:gmp:6.2.0-r0:*:*:*:*:*:*:*")),
						must(pkg.NewCPE("cpe:2.3:a:gmp:gmp:6.2.0-r0:*:*:*:*:*:*:*")),
					},
					PURL:     "pkg:alpine/gmp@6.2.0-r0?arch=x86_64",
					Metadata: DpkgMetadata{Source: "a-source"},
				},
				{
					id:      1,
					Name:    "gmp",
					Version: "6.2.0-r0",
					Locations: []source.Location{
						{
							Path:         "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						},
					},
					Language: "the-lang",
					Licenses: []string{
						"LGPL-3.0-or-later",
					},
					Type: "java-archive",
					CPEs: []pkg.CPE{
						must(pkg.NewCPE("cpe:2.3:a:*:gmp:6.2.0-r0:*:*:*:*:*:*:*")),
						must(pkg.NewCPE("cpe:2.3:a:gmp:gmp:6.2.0-r0:*:*:*:*:*:*:*")),
					},
					PURL: "pkg:alpine/gmp@6.2.0-r0?arch=x86_64",
					Metadata: JavaMetadata{
						PomArtifactID: "aid",
						PomGroupID:    "gid",
						ManifestName:  "a-name",
					},
				},
			},
			Context: Context{
				Source: &source.Metadata{
					Scheme: source.ImageScheme,
					ImageMetadata: source.ImageMetadata{
						UserInput: "alpine:fake",
						Scope:     "Squashed",
						Layers: []source.LayerMetadata{
							{
								MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
								Digest:    "sha256:50644c29ef5a27c9a40c393a73ece2479de78325cae7d762ef3cdc19bf42dd0a",
								Size:      5570176,
							},
						},
						Size:           15879684,
						ID:             "sha256:fadf1294c09213b20d4d6fc84109584e1c102d185c2cae15144a87d29de65c6d",
						ManifestDigest: "sha256:1f6495428fb363e2d233e5df078b2b200635c4e51f0a3be34ecf09d44b547590",
						MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
						Tags: []string{
							"alpine:fake",
						},
						//RawManifest: []byte("eyJzY2hlbWFWZXJzaW9uIjoyLCJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQuZG9ja2VyLmRpc3RyaWJ1dGlvbi5tYW5pZmVzdC52Mitqc29uIiwiY29uZmlnIjp7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuY29udGFpbmVyLmltYWdlLnYxK2pzb24iLCJzaXplIjoyMTE2LCJkaWdlc3QiOiJzaGEyNTY6ZmFkZjEyOTRjMDkyMTNiMjBkNGQ2ZmM4NDEwOTU4NGUxYzEwMmQxODVjMmNhZTE1MTQ0YTg3ZDI5ZGU2NWM2ZCJ9LCJsYXllcnMiOlt7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLCJzaXplIjo1ODQ0OTkyLCJkaWdlc3QiOiJzaGEyNTY6NTA2NDRjMjllZjVhMjdjOWE0MGMzOTNhNzNlY2UyNDc5ZGU3ODMyNWNhZTdkNzYyZWYzY2RjMTliZjQyZGQwYSJ9LHsibWVkaWFUeXBlIjoiYXBwbGljYXRpb24vdm5kLmRvY2tlci5pbWFnZS5yb290ZnMuZGlmZi50YXIuZ3ppcCIsInNpemUiOjE2NzkzNiwiZGlnZXN0Ijoic2hhMjU2OmNjMGZmMWRkYWQ2ZmU0OTc4ZDgzMjYzMGE5MzAzODgzYWRjNTZlZGZjNzdjYWEzNjkyMjM5YzJkODFjZjVkMDAifSx7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLCJzaXplIjoxMDE2Njc4NCwiZGlnZXN0Ijoic2hhMjU2OjNkZDJkYjQ4M2JjOWQ2YjU2MWNlNWNjMTEwNWUwYjZkMTk2MWNhMjQ5YTczNmJiYTgzNzFhYjI4ZWEzMDRmODQifSx7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLCJzaXplIjoyMjUyOCwiZGlnZXN0Ijoic2hhMjU2OjkzY2Y0Y2ZiNjczYzdlMTZhOWU3NGY3MzFkNjc2N2I3MGI5MmEwYjdjOWY1OWQwNmVmZDcyZmJmZjUzNTM3MWMifV19"),
						//RawConfig:   []byte("eyJhcmNoaXRlY3R1cmUiOiJhbWQ2NCIsImNvbmZpZyI6eyJIb3N0bmFtZSI6IiIsIkRvbWFpbm5hbWUiOiIiLCJVc2VyIjoiIiwiQXR0YWNoU3RkaW4iOmZhbHNlLCJBdHRhY2hTdGRvdXQiOmZhbHNlLCJBdHRhY2hTdGRlcnIiOmZhbHNlLCJUdHkiOmZhbHNlLCJPcGVuU3RkaW4iOmZhbHNlLCJTdGRpbk9uY2UiOmZhbHNlLCJFbnYiOlsiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iXSwiQ21kIjpbIi9iaW4vc2giXSwiQXJnc0VzY2FwZWQiOnRydWUsIkltYWdlIjoic2hhMjU2OjJjOWQ1MzNiMmI2NGFiMTI4MmFlYTE2ZGYwZjlkYmYwYjNjZDQ3YWMxZTAyYjc1YTM3NjNiMmY0M2NjOWRlNWUiLCJWb2x1bWVzIjpudWxsLCJXb3JraW5nRGlyIjoiIiwiRW50cnlwb2ludCI6bnVsbCwiT25CdWlsZCI6bnVsbCwiTGFiZWxzIjpudWxsfSwiY29udGFpbmVyIjoiYzJlMTM3OTEyYWU2MzdkNzBlMDJhMDVhYWEyM2U3N2JlY2I3Mzg5MDJmZDNjYWMyMjdkNDRlYjdlYzEwMmQ0OCIsImNvbnRhaW5lcl9jb25maWciOnsiSG9zdG5hbWUiOiIiLCJEb21haW5uYW1lIjoiIiwiVXNlciI6IiIsIkF0dGFjaFN0ZGluIjpmYWxzZSwiQXR0YWNoU3Rkb3V0IjpmYWxzZSwiQXR0YWNoU3RkZXJyIjpmYWxzZSwiVHR5IjpmYWxzZSwiT3BlblN0ZGluIjpmYWxzZSwiU3RkaW5PbmNlIjpmYWxzZSwiRW52IjpbIlBBVEg9L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIl0sIkNtZCI6WyIvYmluL3NoIiwiLWMiLCJzZWQgLWkgJ3MvVjowLjkuMTEtcjMvVjowLjkuOS1yMC8nIC9saWIvYXBrL2RiL2luc3RhbGxlZCJdLCJJbWFnZSI6InNoYTI1NjoyYzlkNTMzYjJiNjRhYjEyODJhZWExNmRmMGY5ZGJmMGIzY2Q0N2FjMWUwMmI3NWEzNzYzYjJmNDNjYzlkZTVlIiwiVm9sdW1lcyI6bnVsbCwiV29ya2luZ0RpciI6IiIsIkVudHJ5cG9pbnQiOm51bGwsIk9uQnVpbGQiOm51bGwsIkxhYmVscyI6bnVsbH0sImNyZWF0ZWQiOiIyMDIwLTA5LTI0VDIyOjI2OjQ2LjE2NzYxOTRaIiwiZG9ja2VyX3ZlcnNpb24iOiIxOS4wMy4xMiIsImhpc3RvcnkiOlt7ImNyZWF0ZWQiOiIyMDIwLTA1LTI5VDIxOjE5OjQ2LjE5MjA0NTk3MloiLCJjcmVhdGVkX2J5IjoiL2Jpbi9zaCAtYyAjKG5vcCkgQUREIGZpbGU6YzkyYzI0ODIzOWY4YzdiOWIzYzA2NzY1MDk1NDgxNWYzOTFiN2JjYjA5MDIzZjk4NDk3MmMwODJhY2UyYThkMCBpbiAvICJ9LHsiY3JlYXRlZCI6IjIwMjAtMDUtMjlUMjE6MTk6NDYuMzYzNTE4MzQ1WiIsImNyZWF0ZWRfYnkiOiIvYmluL3NoIC1jICMobm9wKSAgQ01EIFtcIi9iaW4vc2hcIl0iLCJlbXB0eV9sYXllciI6dHJ1ZX0seyJjcmVhdGVkIjoiMjAyMC0wOS0yNFQyMjoyNjo0NC4zMjk1NTc4WiIsImNyZWF0ZWRfYnkiOiIvYmluL3NoIC1jIHdnZXQgaHR0cDovL2RsLWNkbi5hbHBpbmVsaW51eC5vcmcvYWxwaW5lL3YzLjkvbWFpbi94ODZfNjQvbGlidm5jc2VydmVyLTAuOS4xMS1yMy5hcGsifSx7ImNyZWF0ZWQiOiIyMDIwLTA5LTI0VDIyOjI2OjQ1LjY3MDg1MzhaIiwiY3JlYXRlZF9ieSI6Ii9iaW4vc2ggLWMgYXBrIGFkZCAgbGlidm5jc2VydmVyLTAuOS4xMS1yMy5hcGsifSx7ImNyZWF0ZWQiOiIyMDIwLTA5LTI0VDIyOjI2OjQ2LjE2NzYxOTRaIiwiY3JlYXRlZF9ieSI6Ii9iaW4vc2ggLWMgc2VkIC1pICdzL1Y6MC45LjExLXIzL1Y6MC45LjktcjAvJyAvbGliL2Fway9kYi9pbnN0YWxsZWQifV0sIm9zIjoibGludXgiLCJyb290ZnMiOnsidHlwZSI6ImxheWVycyIsImRpZmZfaWRzIjpbInNoYTI1Njo1MDY0NGMyOWVmNWEyN2M5YTQwYzM5M2E3M2VjZTI0NzlkZTc4MzI1Y2FlN2Q3NjJlZjNjZGMxOWJmNDJkZDBhIiwic2hhMjU2OmNjMGZmMWRkYWQ2ZmU0OTc4ZDgzMjYzMGE5MzAzODgzYWRjNTZlZGZjNzdjYWEzNjkyMjM5YzJkODFjZjVkMDAiLCJzaGEyNTY6M2RkMmRiNDgzYmM5ZDZiNTYxY2U1Y2MxMTA1ZTBiNmQxOTYxY2EyNDlhNzM2YmJhODM3MWFiMjhlYTMwNGY4NCIsInNoYTI1Njo5M2NmNGNmYjY3M2M3ZTE2YTllNzRmNzMxZDY3NjdiNzBiOTJhMGI3YzlmNTlkMDZlZmQ3MmZiZmY1MzUzNzFjIl19fQ=="),
					},
					Path: "",
				},
				Distro: func() *distro.Distro {
					d, _ := distro.NewDistro(distro.Alpine, "3.12.0", "")
					return &d
				}(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fh, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("unable to open fixture: %+v", err)
			}

			pkgs, context, err := parseSyftJSON(fh)
			if err != nil {
				t.Fatalf("unable to parse: %+v", err)
			}

			context.Source.ImageMetadata.RawConfig = nil
			context.Source.ImageMetadata.RawManifest = nil

			for _, d := range deep.Equal(test.Packages, pkgs) {
				t.Errorf("pkg diff: %s", d)
			}

			for _, d := range deep.Equal(test.Context, context) {
				t.Errorf("ctx diff: %s", d)
			}
		})
	}
}
