package pkg

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

const (
	purlInputPrefix       = "purl:"
	singlePurlInputPrefix = "pkg:"
	cpesQualifierKey      = "cpes"
)

func purlProvider(userInput string) ([]Package, Context, error) {
	reader, err := getPurlReader(userInput)
	if err != nil {
		return nil, Context{}, err
	}

	return decodePurlFile(reader)
}

func decodePurlFile(reader io.Reader) ([]Package, Context, error) {
	scanner := bufio.NewScanner(reader)
	var packages []Package
	var ctx Context

	distros := make(map[string]*strset.Set)
	for scanner.Scan() {
		rawLine := scanner.Text()
		p, distroName, distroVersion, err := purlToPackage(rawLine)
		if err != nil {
			return nil, Context{}, err
		}
		if distroName != "" {
			if _, ok := distros[distroName]; !ok {
				distros[distroName] = strset.New()
			}
			distros[distroName].Add(distroVersion)
		}
		if p != nil {
			packages = append(packages, *p)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, ctx, err
	}

	// if there is one distro (with one version) represented, use that
	if len(distros) == 1 {
		for name, versions := range distros {
			if versions.Size() == 1 {
				version := versions.List()[0]
				var codename string
				// if there are no digits in the version, it is likely a codename
				if !strings.ContainsAny(version, "0123456789") {
					codename = version
					version = ""
				}
				ctx.Distro = &linux.Release{
					Name:            name,
					ID:              name,
					IDLike:          []string{name},
					Version:         version,
					VersionCodename: codename,
				}
			}
		}
	}

	return packages, ctx, nil
}

func purlToPackage(rawLine string) (*Package, string, string, error) {
	purl, err := packageurl.FromString(rawLine)
	if err != nil {
		return nil, "", "", fmt.Errorf("unable to decode purl %s: %w", rawLine, err)
	}

	var cpes []cpe.CPE
	var upstreams []UpstreamPackage
	var distroName, distroVersion string
	epoch := "0"

	pkgType := pkg.TypeByName(purl.Type)

	for _, qualifier := range purl.Qualifiers {
		switch qualifier.Key {
		case cpesQualifierKey:
			rawCpes := strings.Split(qualifier.Value, ",")
			for _, rawCpe := range rawCpes {
				c, err := cpe.New(rawCpe, "")
				if err != nil {
					return nil, "", "", fmt.Errorf("unable to decode cpe %s in purl %s: %w", rawCpe, rawLine, err)
				}
				cpes = append(cpes, c)
			}
		case pkg.PURLQualifierEpoch:
			epoch = qualifier.Value
		case pkg.PURLQualifierUpstream:
			upstreams = append(upstreams, parseUpstream(purl.Name, qualifier.Value, pkgType)...)
		case pkg.PURLQualifierDistro:
			name, version := parseDistroQualifier(qualifier.Value)
			if name != "" && version != "" {
				distroName = name
				distroVersion = version
			}
		}
	}

	version := purl.Version
	if purl.Type == packageurl.TypeRPM && !strings.HasPrefix(purl.Version, fmt.Sprintf("%s:", epoch)) {
		version = fmt.Sprintf("%s:%s", epoch, purl.Version)
	}

	return &Package{
		ID:        ID(purl.String()),
		CPEs:      cpes,
		Name:      purl.Name,
		Version:   version,
		Type:      pkgType,
		Language:  pkg.LanguageByName(purl.Type),
		PURL:      purl.String(),
		Upstreams: upstreams,
	}, distroName, distroVersion, nil
}

func parseDistroQualifier(value string) (string, string) {
	fields := strings.SplitN(value, "-", 2)
	switch len(fields) {
	case 2:
		return fields[0], fields[1]
	case 1:
		return fields[0], ""
	}
	return "", ""
}

func parseUpstream(pkgName string, value string, pkgType pkg.Type) []UpstreamPackage {
	if pkgType == pkg.RpmPkg {
		return handleSourceRPM(pkgName, value)
	}
	return handleDefaultUpstream(pkgName, value)
}

func handleDefaultUpstream(pkgName string, value string) []UpstreamPackage {
	fields := strings.Split(value, "@")
	switch len(fields) {
	case 2:
		if fields[0] == pkgName {
			return nil
		}
		return []UpstreamPackage{
			{
				Name:    fields[0],
				Version: fields[1],
			},
		}
	case 1:
		if fields[0] == pkgName {
			return nil
		}
		return []UpstreamPackage{
			{
				Name: fields[0],
			},
		}
	}
	return nil
}

func getPurlReader(userInput string) (r io.Reader, err error) {
	switch {
	case strings.HasPrefix(userInput, purlInputPrefix):
		path := strings.TrimPrefix(userInput, purlInputPrefix)
		return openPurlFile(path)
	case strings.HasPrefix(userInput, singlePurlInputPrefix):
		return strings.NewReader(userInput), nil
	}
	return nil, errDoesNotProvide
}

func openPurlFile(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open purls: %w", err)
	}

	f, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", expandedPath, err)
	}

	return f, nil
}
