package version

import (
	"fmt"

	bitnami "github.com/bitnami/go-version/pkg/version"
)

func newBitnamiVersion(raw string) (*semanticVersion, error) {
	bitnamiVersion, err := bitnami.Parse(raw)
	if err != nil {
		return nil, err
	}

	// We can't assume Bitnami revisions can potentially address a
	// known vulnerability given Bitnami package revisions use
	// exactly the same upstream source code used to create the
	// previous version. Then, we discard it.
	return newSemanticVersion(fmt.Sprintf("%d.%d.%d", bitnamiVersion.Major(), bitnamiVersion.Minor(), bitnamiVersion.Patch()))
}
