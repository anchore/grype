package pkg

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const cpeInputPrefix = "cpe:"

type CPELiteralMetadata struct {
	CPE string
}

func cpeProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	reader, ctx, err := getCPEReader(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	s, _, _, err := format.Decode(reader)
	if s == nil {
		return nil, Context{}, nil, fmt.Errorf("unable to decode cpe: %w", err)
	}

	return FromCollection(s.Artifacts.Packages, config.SynthesisConfig), ctx, s, nil
}

func getCPEReader(userInput string) (r io.Reader, ctx Context, err error) {
	if strings.HasPrefix(userInput, cpeInputPrefix) {
		ctx.Source = &source.Description{
			Metadata: CPELiteralMetadata{
				CPE: userInput,
			},
		}
		return strings.NewReader(userInput), ctx, nil
	}
	return nil, ctx, errDoesNotProvide
}
