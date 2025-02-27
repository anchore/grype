package pkg

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const cpeInputPrefix = "cpe:"

type CPELiteralMetadata struct {
	CPE string
}

func cpeProvider(userInput string) ([]Package, Context, *sbom.SBOM, error) {
	reader, ctx, err := getCPEReader(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	return decodeCPEsFromReader(reader, ctx)
}

func getCPEReader(userInput string) (r io.Reader, ctx Context, err error) {
	if strings.HasPrefix(userInput, cpeInputPrefix) {
		ctx.Source = &source.Description{
			Metadata: CPELiteralMetadata{
				CPE: userInput,
			},
		}
		return strings.NewReader(userInput), ctx, nil
	}
	return nil, ctx, errDoesNotProvide
}

func decodeCPEsFromReader(reader io.Reader, ctx Context) ([]Package, Context, *sbom.SBOM, error) {
	scanner := bufio.NewScanner(reader)
	var packages []Package
	var syftPkgs []pkg.Package

	for scanner.Scan() {
		rawLine := scanner.Text()
		p, syftPkg, err := cpeToPackage(rawLine)
		if err != nil {
			return nil, Context{}, nil, err
		}

		if p != nil {
			packages = append(packages, *p)
		}
		if syftPkg != nil {
			syftPkgs = append(syftPkgs, *syftPkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, Context{}, nil, err
	}

	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(syftPkgs...),
		},
	}

	return packages, ctx, s, nil
}

func cpeToPackage(rawLine string) (*Package, *pkg.Package, error) {
	c, err := cpe.New(rawLine, "")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode cpe %q: %w", rawLine, err)
	}

	syftPkg := pkg.Package{
		Name:    c.Attributes.Product,
		Version: c.Attributes.Version,
		CPEs:    []cpe.CPE{c},
		Type:    inferPackageType(c.Attributes.TargetSW),
	}

	syftPkg.SetID()

	return &Package{
		ID:       ID(c.Attributes.BindToFmtString()),
		CPEs:     syftPkg.CPEs,
		Name:     syftPkg.Name,
		Version:  syftPkg.Version,
		Type:     syftPkg.Type,
		Language: syftPkg.Language,
	}, &syftPkg, nil
}

// inferPackageType is derived from looking at target_software attributes in the NVD dataset
// TODO: ideally this would be driven from the store, where we can resolve ecosystem aliases directly
func inferPackageType(tsw string) pkg.Type {
	tsw = strings.NewReplacer("-", "_", " ", "").Replace(strings.ToLower(tsw))
	switch tsw {
	case "alpine", "apk":
		return pkg.ApkPkg
	case "debian", "dpkg":
		return pkg.DebPkg
	case "java", "maven", "ant", "gradle", "jenkins", "jenkins_ci", "kafka", "logstash", "mule", "nifi", "solr", "spark", "storm", "struts", "tomcat", "zookeeper", "log4j":
		return pkg.JavaPkg
	case "javascript", "node", "nodejs", "node.js", "npm", "yarn", "apache", "jquery", "next.js", "prismjs":
		return pkg.NpmPkg
	case "c", "c++", "c/c++", "conan", "gnu_c++", "qt":
		return pkg.ConanPkg
	case "dart":
		return pkg.DartPubPkg
	case "redhat", "rpm", "redhat_enterprise_linux", "rhel", "suse", "suse_linux", "opensuse", "opensuse_linux", "fedora", "centos", "oracle_linux", "ol":
		return pkg.RpmPkg
	case "elixir", "hex":
		return pkg.HexPkg
	case "erlang":
		return pkg.ErlangOTPPkg
	case ".net", ".net_framework", "asp", "asp.net", "dotnet", "dotnet_framework", "c#", "csharp", "nuget":
		return pkg.DotnetPkg
	case "ruby", "gem", "nokogiri", "ruby_on_rails":
		return pkg.GemPkg
	case "rust", "cargo", "crates":
		return pkg.RustPkg
	case "python", "pip", "pypi", "flask":
		return pkg.PythonPkg
	case "kb", "knowledgebase", "msrc", "mskb", "microsoft":
		return pkg.KbPkg
	case "portage", "gentoo":
		return pkg.PortagePkg
	case "go", "golang", "gomodule":
		return pkg.GoModulePkg
	case "linux_kernel", "linux", "z/linux":
		return pkg.LinuxKernelPkg
	case "php":
		return pkg.PhpComposerPkg
	case "swift":
		return pkg.SwiftPkg
	case "wordpress", "wordpress_plugin", "wordpress_":
		return pkg.WordpressPluginPkg
	case "lua", "luarocks":
		return pkg.LuaRocksPkg
	}
	return ""
}
