package pkg

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/format"
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

type PURLFileMetadata struct {
	Path string
}

func purlProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	reader, ctx, err := getPurlReader(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	s, _, _, err := format.Decode(reader)
	if s == nil {
		return nil, Context{}, nil, fmt.Errorf("unable to decode purl: %w", err)
	}

	return FromCollection(s.Artifacts.Packages, config.SynthesisConfig), ctx, s, nil
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
