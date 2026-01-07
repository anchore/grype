package internal

import (
	"fmt"

	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func ProviderModel(state provider.State) *grypeDB.Provider {
	var digest string
	if state.Listing != nil {
		if state.Listing.Algorithm != "" && state.Listing.Digest != "" {
			digest = state.Listing.Algorithm + ":" + state.Listing.Digest
		}
	}
	return &grypeDB.Provider{
		ID:           state.Provider,
		Version:      fmt.Sprintf("%d", state.Version),
		Processor:    state.Processor,
		DateCaptured: &state.Timestamp,
		InputDigest:  digest,
	}
}
