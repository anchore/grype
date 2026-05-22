package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/build/pull"
)

// stringMap is a string->string map that renders as inline YAML (e.g. "{}" or
// "{k: v, k2: v2}") when formatted with %v, so that `grype config` produces
// output that is itself valid YAML. The default Go formatter for map types
// would emit "map[]" which round-trips back through YAML as a string.
type stringMap map[string]string

func (m stringMap) String() string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(m))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", k, m[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// DatabaseBuild holds the configuration for `grype db build`, the unified
// pull -> write -> package pipeline. The shape mirrors grype-db's historical
// configuration (provider/pull/build/package) so that existing config files
// remain familiar; individual phases can be skipped via --skip.
type DatabaseBuild struct {
	// build-time options (covers the "write" phase)
	SchemaVersion        int      `yaml:"schema-version" json:"schema-version" mapstructure:"schema-version"`
	Dir                  string   `yaml:"dir" json:"dir" mapstructure:"dir"`
	BatchSize            int      `yaml:"batch-size" json:"batch-size" mapstructure:"batch-size"`
	IncludeCPEParts      []string `yaml:"include-cpe-parts" json:"include-cpe-parts" mapstructure:"include-cpe-parts"`
	InferNVDFixVersions  bool     `yaml:"infer-nvd-fix-versions" json:"infer-nvd-fix-versions" mapstructure:"infer-nvd-fix-versions"`
	Hydrate              bool     `yaml:"hydrate" json:"hydrate" mapstructure:"hydrate"`
	FailOnMissingFixDate bool     `yaml:"fail-on-missing-fix-date" json:"fail-on-missing-fix-date" mapstructure:"fail-on-missing-fix-date"`

	// pipeline control
	Skip []string `yaml:"skip" json:"skip" mapstructure:"skip"`

	// archive options (covers the "package" phase)
	ArchiveExtension   string    `yaml:"archive-extension" json:"archive-extension" mapstructure:"archive-extension"`
	CompressorCommands stringMap `yaml:"compressor-commands" json:"compressor-commands" mapstructure:"compressor-commands"`

	// nested config for the pull phase + providers
	Pull     DatabaseBuildPull     `yaml:"pull" json:"pull" mapstructure:"pull"`
	Provider DatabaseBuildProvider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

type DatabaseBuildPull struct {
	Parallelism int `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`
}

type DatabaseBuildProvider struct {
	Root          string                    `yaml:"root" json:"root" mapstructure:"root"`
	IncludeFilter []string                  `yaml:"include-filter" json:"include-filter" mapstructure:"include-filter"`
	Vunnel        DatabaseBuildVunnel       `yaml:"vunnel" json:"vunnel" mapstructure:"vunnel"`
	Configs       []pull.ProviderRunConfig  `yaml:"configs" json:"configs" mapstructure:"configs"`
}

type DatabaseBuildVunnel struct {
	Config           string            `yaml:"config" json:"config" mapstructure:"config"`
	Executor         string            `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerImage      string            `yaml:"docker-image" json:"docker-image" mapstructure:"docker-image"`
	DockerTag        string            `yaml:"docker-tag" json:"docker-tag" mapstructure:"docker-tag"`
	GenerateConfigs  bool              `yaml:"generate-configs" json:"generate-configs" mapstructure:"generate-configs"`
	ExcludeProviders []string          `yaml:"exclude-providers" json:"exclude-providers" mapstructure:"exclude-providers"`
	Env              stringMap `yaml:"env,omitempty" json:"env,omitempty" mapstructure:"env"`
}

var _ interface {
	clio.FlagAdder
	clio.FieldDescriber
	clio.PostLoader
} = (*DatabaseBuild)(nil)

// PostLoad flattens any comma-separated entries in --provider-name and --skip
// so that "-p alpine,alma,rhel" behaves the same as "-p alpine -p alma -p rhel"
// (matching the convention used by grype's --from flag).
func (o *DatabaseBuild) PostLoad() error {
	o.Provider.IncludeFilter = flattenCSV(o.Provider.IncludeFilter)
	o.Skip = flattenCSV(o.Skip)
	return nil
}

func flattenCSV(in []string) []string {
	if len(in) == 0 {
		return in
	}
	var out []string
	for _, v := range in {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func DefaultDatabaseBuild() *DatabaseBuild {
	return &DatabaseBuild{
		SchemaVersion:        db.DefaultSchemaVersion,
		Dir:                  "./build",
		BatchSize:            db.DefaultBatchSize,
		IncludeCPEParts:      []string{"a", "h", "o"},
		InferNVDFixVersions:  true,
		Hydrate:              false,
		FailOnMissingFixDate: false,
		Skip:                 nil,
		CompressorCommands: stringMap{},
		Pull: DatabaseBuildPull{
			Parallelism: 4,
		},
		Provider: DatabaseBuildProvider{
			Root: "./data",
			Vunnel: DatabaseBuildVunnel{
				Executor:         "docker",
				DockerImage:      "ghcr.io/anchore/vunnel",
				DockerTag:        "latest",
				GenerateConfigs:  false,
				ExcludeProviders: []string{"centos"},
				Env:              stringMap{},
			},
		},
	}
}

func (o *DatabaseBuild) AddFlags(flags clio.FlagSet) {
	flags.IntVarP(&o.SchemaVersion, "schema", "s",
		"DB schema version to build for")

	flags.StringVarP(&o.Dir, "dir", "d",
		"directory where the database is written")

	flags.BoolVarP(&o.Provider.Vunnel.GenerateConfigs, "generate-providers-from-vunnel", "g",
		"generate provider configs from 'vunnel list' output")

	flags.StringVarP(&o.ArchiveExtension, "archive-extension", "e",
		"override the extension used during DB archiving (default chosen by the DB schema, typically 'tar.zst')")

	flags.StringArrayVarP(&o.Skip, "skip", "",
		"comma-separated phases of the build pipeline to skip; one or more of: pull, validate, write, package")

	flags.StringArrayVarP(&o.Provider.IncludeFilter, "provider-name", "p",
		"one or more provider names to filter the build to (default: empty = all)")
}

func (o *DatabaseBuild) DescribeFields(d clio.FieldDescriptionSet) {
	d.Add(&o.SchemaVersion, `DB schema version to build for`)
	d.Add(&o.Dir, `directory to write the built SQLite DB into`)
	d.Add(&o.BatchSize, `number of database operations to batch before flushing to disk
(balances throughput with memory usage; 0 = library default)`)
	d.Add(&o.IncludeCPEParts, `CPE parts (a, h, o) to include when emitting CPE-based vulnerability matches`)
	d.Add(&o.InferNVDFixVersions, `derive missing NVD fix versions from CVE configurations when building the DB`)
	d.Add(&o.Hydrate, `populate post-build derived data (only applies for schemas > 5)`)
	d.Add(&o.FailOnMissingFixDate, `fail the build if any fix entry lacks a known available date`)
	d.Add(&o.Skip, `phases of the build pipeline to skip (pull, validate, write, package)`)
	d.Add(&o.ArchiveExtension, `archive extension used during DB packaging; empty means the schema default`)
	d.Add(&o.CompressorCommands, `external commands to use for compressing archives, keyed by extension`)

	d.Add(&o.Pull.Parallelism, `number of vulnerability providers to update concurrently during the pull phase`)

	d.Add(&o.Provider.Root, `directory holding the vulnerability provider workspace (see vunnel provider-workspace-state schema)`)
	d.Add(&o.Provider.IncludeFilter, `restrict the build to these provider names (empty = include all)`)
	d.Add(&o.Provider.Configs, `manually crafted provider configurations (advanced use only)`)

	d.Add(&o.Provider.Vunnel.Config, `path to a vunnel configuration file to mount/use when running vunnel`)
	d.Add(&o.Provider.Vunnel.Executor, `how to run vunnel: 'docker' (default), 'podman', or 'local' (use vunnel from $PATH)`)
	d.Add(&o.Provider.Vunnel.DockerImage, `docker image to use when running vunnel via docker/podman`)
	d.Add(&o.Provider.Vunnel.DockerTag, `image tag for the vunnel docker image`)
	d.Add(&o.Provider.Vunnel.GenerateConfigs, `generate additional provider configurations from 'vunnel list' output`)
	d.Add(&o.Provider.Vunnel.ExcludeProviders, `providers to exclude from 'vunnel list' output (only when generate-configs is true)`)
	d.Add(&o.Provider.Vunnel.Env, `environment variables to pass to the vunnel process`)
}
