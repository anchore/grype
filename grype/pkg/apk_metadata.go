package pkg

type ApkMetadata struct {
	OriginPackage string
}

func apkMetadataFromPURL(p string) *ApkMetadata {
	qualifiers := getPURLQualifiers(p)
	upstream := qualifiers[purlUpstreamQualifier]
	if upstream == "" {
		return nil
	}
	return &ApkMetadata{
		OriginPackage: upstream,
	}
}
