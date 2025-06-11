package version

import (
	"fmt"

	hashiVer "github.com/anchore/go-version"
)

type semanticVersion struct {
	verObj *hashiVer.Version
}

func newSemanticVersion(raw string) (*semanticVersion, error) {
	verObj, err := hashiVer.NewVersion(normalizer.Replace(raw))
	if err != nil {
		return nil, fmt.Errorf("unable to create semver obj: %w", err)
	}
	return &semanticVersion{
		verObj: verObj,
	}, nil
}

func (v *semanticVersion) Compare(other *Version) (int, error) {
	if other != nil && other.Format == BitnamiFormat {
		transformed, err := newBitnamiVersion(other.Raw)
		if err != nil {
			return -1, fmt.Errorf("unable to transform bitnami version: %w", err)
		}

		return transformed.verObj.Compare(v.verObj), nil
	}

	other, err := finalizeComparisonVersion(other, SemanticFormat)
	if err != nil {
		return -1, err
	}

	if other.rich.semVer == nil {
		return -1, fmt.Errorf("given empty semanticVersion object")
	}

	return other.rich.semVer.verObj.Compare(v.verObj), nil
}
