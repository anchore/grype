package internal

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// CPETargetSoftwareToPackageType is derived from looking at target_software attributes in the NVD dataset
// TODO: ideally this would be driven from the store, where we can resolve ecosystem aliases directly
func CPETargetSoftwareToPackageType(tsw string) pkg.Type {
	tsw = strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(tsw))
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
