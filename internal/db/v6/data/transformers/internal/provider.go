package internal

import (
	"fmt"

	"github.com/anchore/grype/grype/db/data/provider"
	v6 "github.com/anchore/grype/internal/db/v6"
)

func ProviderModel(state provider.State) *v6.Provider {
	var digest string
	if state.Listing != nil {
		if state.Listing.Algorithm != "" && state.Listing.Digest != "" {
			digest = state.Listing.Algorithm + ":" + state.Listing.Digest
		}
	}
	return &v6.Provider{
		ID:           state.Provider,
		Version:      fmt.Sprintf("%d", state.Version),
		Processor:    state.Processor,
		DateCaptured: &state.Timestamp,
		InputDigest:  digest,
	}
}
