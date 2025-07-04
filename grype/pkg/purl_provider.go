package pkg

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/format"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	purlInputPrefix       = "purl:"
	singlePurlInputPrefix = "pkg:"
)

type PURLLiteralMetadata struct {
	PURL string
}

func purlEnhancers(applyChannel func(*distro.Distro)) []Enhancer {
	return []Enhancer{setUpstreamsFromPURL, setDistroFromPURL(applyChannel)}
}

func purlProvider(userInput string, config ProviderConfig, applyChannel func(*distro.Distro)) ([]Package, Context, *sbom.SBOM, error) {
	reader, ctx, err := getPurlReader(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	s, _, _, err := format.Decode(reader)
	if s == nil {
		return nil, Context{}, nil, fmt.Errorf("unable to decode purl: %w", err)
	}

	return FromCollection(s.Artifacts.Packages, config.SynthesisConfig, purlEnhancers(applyChannel)...), ctx, s, nil
}

func getPurlReader(userInput string) (r io.Reader, ctx Context, err error) {
	if strings.HasPrefix(userInput, singlePurlInputPrefix) {
		ctx.Source = &source.Description{
			Metadata: PURLLiteralMetadata{
				PURL: userInput,
			},
		}
		return strings.NewReader(userInput), ctx, nil
	}
	return nil, ctx, errDoesNotProvide
}

func setUpstreamsFromPURL(out *Package, purl packageurl.PackageURL, syftPkg syftPkg.Package) {
	if len(out.Upstreams) == 0 {
		out.Upstreams = upstreamsFromPURL(purl, syftPkg.Type)
	}
}

// upstreamsFromPURL reads any additional data Grype can use, which is ignored by Syft's PURL conversion
func upstreamsFromPURL(purl packageurl.PackageURL, pkgType syftPkg.Type) (upstreams []UpstreamPackage) {
	for _, qualifier := range purl.Qualifiers {
		if qualifier.Key == syftPkg.PURLQualifierUpstream {
			for _, newUpstream := range parseUpstream(purl.Name, qualifier.Value, pkgType) {
				if slices.Contains(upstreams, newUpstream) {
					continue
				}
				upstreams = append(upstreams, newUpstream)
			}
		}
	}
	return upstreams
}

func setDistroFromPURL(applyChannel func(*distro.Distro)) func(out *Package, purl packageurl.PackageURL, _ syftPkg.Package) {
	return func(out *Package, purl packageurl.PackageURL, _ syftPkg.Package) {
		if out.Distro == nil {
			out.Distro = distroFromPURL(purl)
			applyChannel(out.Distro)
		}
	}
}

// distroFromPURL reads distro data for Grype can use, which is ignored by Syft's PURL conversion
func distroFromPURL(purl packageurl.PackageURL) (d *distro.Distro) {
	var distroName, distroVersion string

	for _, qualifier := range purl.Qualifiers {
		if qualifier.Key == syftPkg.PURLQualifierDistro {
			fields := strings.SplitN(qualifier.Value, "-", 2)
			distroName = fields[0]
			if len(fields) > 1 {
				distroVersion = fields[1]
			}
		}
	}

	if distroName != "" {
		d = distro.NewFromNameVersion(distroName, distroVersion)
	}

	return d
}
