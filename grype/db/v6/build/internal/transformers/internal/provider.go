package internal

import (
	"fmt"

	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
)

func ProviderModel(state provider.State) *db.Provider {
	var digest string
	if state.Listing != nil {
		if state.Listing.Algorithm != "" && state.Listing.Digest != "" {
			digest = state.Listing.Algorithm + ":" + state.Listing.Digest
		}
	}
	return &db.Provider{
		ID:           state.Provider,
		Version:      fmt.Sprintf("%d", state.Version),
		Processor:    state.Processor,
		DateCaptured: &state.Timestamp,
		InputDigest:  digest,
	}
}
