package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/grype/grype/cpe"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	syftJson "github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/source"
)

func syftJSONProvider(config providerConfig) ([]Package, Context, error) {
	var reader io.Reader
	if config.reader != nil {
		// the caller is explicitly hinting to use the given reader as input
		reader = config.reader
	} else {
		// try and get a reader from the description
		if strings.HasPrefix(config.userInput, "sbom:") {
			// the user has explicitly hinted this is an sbom, if there is an issue return the error
			filepath := strings.TrimPrefix(config.userInput, "sbom:")
			sbomReader, err := os.Open(filepath)
			if err != nil {
				return nil, Context{}, fmt.Errorf("user hinted 'sbom:' but could read SBOM file: %w", err)
			}
			reader = sbomReader
		}

		// the user has not hinted that this may be a sbom, but lets try that first...
		if sbomReader, err := os.Open(config.userInput); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, Context{}, errDoesNotProvide
			}
		} else {
			reader = sbomReader
		}
	}

	return parseSyftJSON(reader)
}

// partialSyftDoc is the final package shape for a select elements from a syft JSON document.
type partialSyftDoc struct {
	Source    syftJson.Source       `json:"source"`
	Artifacts []partialSyftPackage  `json:"artifacts"`
	Distro    syftJson.Distribution `json:"distro"`
}

// partialSyftPackage is the final package shape for a select elements from a syft JSON package.
type partialSyftPackage struct {
	packageBasicMetadata
	packageCustomMetadata
}

// packageBasicMetadata contains non-ambiguous values (type-wise) from pkg.Package.
type packageBasicMetadata struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      pkg.Type          `json:"type"`
	Locations []source.Location `json:"locations"`
	Licenses  []string          `json:"licenses"`
	Language  pkg.Language      `json:"language"`
	CPEs      []string          `json:"cpes"`
	PURL      string            `json:"purl"`
}

// packageCustomMetadata contains ambiguous values (type-wise) from pkg.Package.
type packageCustomMetadata struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     interface{}      `json:"metadata"`
}

// packageMetadataUnpacker is all values needed from Package to disambiguate ambiguous fields during json unmarshaling.
type packageMetadataUnpacker struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     json.RawMessage  `json:"metadata"`
}

// JavaMetadata encapsulates all Java ecosystem metadata for a package as well as an (optional) parent relationship.
type partialSyftJavaMetadata struct {
	VirtualPath   string                    `json:"virtualPath"`
	Manifest      *partialSyftJavaManifest  `mapstructure:"Manifest" json:"manifest,omitempty"`
	PomProperties *partialSyftPomProperties `mapstructure:"PomProperties" json:"pomProperties,omitempty"`
}

// PomProperties represents the fields of interest extracted from a Java archive's pom.xml file.
type partialSyftPomProperties struct {
	GroupID    string `mapstructure:"groupId" json:"groupId"`
	ArtifactID string `mapstructure:"artifactId" json:"artifactId"`
}

// JavaManifest represents the fields of interest extracted from a Java archive's META-INF/MANIFEST.MF file.
type partialSyftJavaManifest struct {
	Main map[string]string `json:"main,omitempty"`
}

// String returns the stringer representation for a syft package.
func (p partialSyftPackage) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

// UnmarshalJSON is a custom unmarshaller for handling basic values and values with ambiguous types.
func (p *partialSyftPackage) UnmarshalJSON(b []byte) error {
	var basic packageBasicMetadata
	if err := json.Unmarshal(b, &basic); err != nil {
		return err
	}
	p.packageBasicMetadata = basic

	var unpacker packageMetadataUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		return err
	}

	p.MetadataType = unpacker.MetadataType

	switch p.MetadataType {
	case pkg.RpmdbMetadataType:
		var payload RpmdbMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.DpkgMetadataType:
		var payload DpkgMetadata
		if err := json.Unmarshal(unpacker.Metadata, &payload); err != nil {
			return err
		}
		p.Metadata = payload
	case pkg.JavaMetadataType:
		var partialPayload partialSyftJavaMetadata
		if err := json.Unmarshal(unpacker.Metadata, &partialPayload); err != nil {
			return err
		}

		var artifact, group, name string
		if partialPayload.PomProperties != nil {
			artifact = partialPayload.PomProperties.ArtifactID
			group = partialPayload.PomProperties.GroupID
		}

		if partialPayload.Manifest != nil {
			if n, ok := partialPayload.Manifest.Main["Name"]; ok {
				name = n
			}
		}

		p.Metadata = JavaMetadata{
			PomArtifactID: artifact,
			PomGroupID:    group,
			ManifestName:  name,
		}
	case "":
		// there may be packages with no metadata, which is OK
	default:
		return fmt.Errorf("unsupported package metadata type: %+v", p.MetadataType)
	}

	return nil
}

// parseSyftJson attempts to loosely parse the available JSON for only the fields needed, not the exact syft JSON shape.
// This allows for some resiliency as the syft document shape changes over time (but not fool-proof).
func parseSyftJSON(reader io.Reader) ([]Package, Context, error) {
	var doc partialSyftDoc
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&doc); err != nil {
		return nil, Context{}, errDoesNotProvide
	}

	var packages = make([]Package, len(doc.Artifacts))
	for i, a := range doc.Artifacts {
		cpes, err := cpe.NewSlice(a.CPEs...)
		if err != nil {
			return nil, Context{}, err
		}

		packages[i] = Package{
			id:        ID(i),
			Name:      a.Name,
			Version:   a.Version,
			Locations: a.Locations,
			Language:  a.Language,
			Licenses:  a.Licenses,
			Type:      a.Type,
			CPEs:      cpes,
			PURL:      a.PURL,
			Metadata:  a.Metadata,
		}
	}

	var theDistro *distro.Distro
	if doc.Distro.Name != "" {
		d, err := distro.NewDistro(distro.Type(doc.Distro.Name), doc.Distro.Version, doc.Distro.IDLike)
		if err != nil {
			return nil, Context{}, err
		}
		theDistro = &d
	}

	srcMetadata := doc.Source.ToSourceMetadata()

	return packages, Context{
		Source: &srcMetadata,
		Distro: theDistro,
	}, nil
}
