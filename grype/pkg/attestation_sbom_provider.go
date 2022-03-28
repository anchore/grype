package pkg

func syftAttestationProvider(userInput string, config ProviderConfig) ([]Package, Context, error) {
	if explicitlySpecifySBOMAttestation(userInput) {
		// filepath := strings.TrimPrefix(userInput, "sbom-att:")
		// TODO: validate signature, return sbom packages
	}

	return nil, Context{}, errDoesNotProvide
}
