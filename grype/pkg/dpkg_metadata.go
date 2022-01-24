package pkg

import "strings"

type DpkgMetadata struct {
	Source        string
	SourceVersion string
}

func dpkgMetadataFromPURL(p string) *DpkgMetadata {
	qualifiers := getPURLQualifiers(p)
	upstream := qualifiers[purlUpstreamQualifier]
	if upstream == "" {
		return nil
	}

	source := upstream
	sourceVersion := ""

	fields := strings.SplitN(upstream, "@", 2)
	if len(fields) > 1 {
		source = fields[0]
		sourceVersion = fields[1]
	}

	return &DpkgMetadata{
		Source:        source,
		SourceVersion: sourceVersion,
	}
}
