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

// DatabaseBuild holds the configuration shared by the `grype db-builder`
// subcommands (pull, build, package). Each subcommand reads the subset of
// fields it needs; flags are registered on a single AddFlags so the YAML
// shape stays consistent across subcommands.
type DatabaseBuild struct {
	// build-time options (used by `db-builder build`)
	SchemaVersion        int      `yaml:"schema-version" json:"schema-version" mapstructure:"schema-version"`
	Dir                  string   `yaml:"dir" json:"dir" mapstructure:"dir"`
	BatchSize            int      `yaml:"batch-size" json:"batch-size" mapstructure:"batch-size"`
	IncludeCPEParts      []string `yaml:"include-cpe-parts" json:"include-cpe-parts" mapstructure:"include-cpe-parts"`
	InferNVDFixVersions  bool     `yaml:"infer-nvd-fix-versions" json:"infer-nvd-fix-versions" mapstructure:"infer-nvd-fix-versions"`
	Hydrate              bool     `yaml:"hydrate" json:"hydrate" mapstructure:"hydrate"`
	FailOnMissingFixDate bool     `yaml:"fail-on-missing-fix-date" json:"fail-on-missing-fix-date" mapstructure:"fail-on-missing-fix-date"`
	SkipValidation       bool     `yaml:"skip-validation" json:"skip-validation" mapstructure:"skip-validation"`

	// archive options (used by `db-builder package`)
	ArchiveExtension   string    `yaml:"archive-extension" json:"archive-extension" mapstructure:"archive-extension"`
	CompressorCommands stringMap `yaml:"compressor-commands" json:"compressor-commands" mapstructure:"compressor-commands"`

	// pull + provider options (used by `db-builder pull` and indirectly by build for state reading)
	Pull     DatabaseBuildPull     `yaml:"pull" json:"pull" mapstructure:"pull"`
	Provider DatabaseBuildProvider `yaml:"provider" json:"provider" mapstructure:"provider"`

	// cache subcommand options (used by `db-builder cache {backup,restore,status,delete}`)
	Cache DatabaseBuildCache `yaml:"cache" json:"cache" mapstructure:"cache"`
}

type DatabaseBuildCache struct {
	Path           string `yaml:"path" json:"path" mapstructure:"path"`
	DeleteExisting bool   `yaml:"delete-existing" json:"delete-existing" mapstructure:"delete-existing"`
	ResultsOnly    bool   `yaml:"results-only" json:"results-only" mapstructure:"results-only"`
	MinRows        int    `yaml:"min-rows" json:"min-rows" mapstructure:"min-rows"`
}

type DatabaseBuildPull struct {
	Parallelism int `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`
}

type DatabaseBuildProvider struct {
	Root          string                   `yaml:"root" json:"root" mapstructure:"root"`
	IncludeFilter []string                 `yaml:"include-filter" json:"include-filter" mapstructure:"include-filter"`
	Vunnel        DatabaseBuildVunnel      `yaml:"vunnel" json:"vunnel" mapstructure:"vunnel"`
	Configs       []pull.ProviderRunConfig `yaml:"configs" json:"configs" mapstructure:"configs"`
}

type DatabaseBuildVunnel struct {
	Config           string    `yaml:"config" json:"config" mapstructure:"config"`
	Executor         string    `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerImage      string    `yaml:"docker-image" json:"docker-image" mapstructure:"docker-image"`
	DockerTag        string    `yaml:"docker-tag" json:"docker-tag" mapstructure:"docker-tag"`
	GenerateConfigs  bool      `yaml:"generate-configs" json:"generate-configs" mapstructure:"generate-configs"`
	ExcludeProviders []string  `yaml:"exclude-providers" json:"exclude-providers" mapstructure:"exclude-providers"`
	Env              stringMap `yaml:"env,omitempty" json:"env,omitempty" mapstructure:"env"`
}

var _ interface {
	clio.FlagAdder
	clio.FieldDescriber
	clio.PostLoader
} = (*DatabaseBuild)(nil)

// PostLoad flattens any comma-separated entries in --provider-name so that
// "-p alpine,alma,rhel" behaves the same as "-p alpine -p alma -p rhel"
// (matching the convention used by grype's --from flag).
func (o *DatabaseBuild) PostLoad() error {
	o.Provider.IncludeFilter = flattenCSV(o.Provider.IncludeFilter)
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
		SkipValidation:       false,
		CompressorCommands:   stringMap{},
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

	flags.BoolVarP(&o.SkipValidation, "skip-validation", "",
		"skip per-provider state validation before writing the DB")

	flags.StringArrayVarP(&o.Provider.IncludeFilter, "provider-name", "p",
		"one or more provider names to filter the build to (default: empty = all)")

	// cache subcommand flags
	flags.StringVarP(&o.Cache.Path, "path", "",
		"path to the cache archive (used by 'db-builder cache backup' and 'restore')")

	flags.BoolVarP(&o.Cache.DeleteExisting, "delete-existing", "",
		"delete any existing provider data before restoring from the cache archive")

	flags.BoolVarP(&o.Cache.ResultsOnly, "results-only", "",
		"archive only the provider 'results' directory (omit raw 'input' data)")

	flags.IntVarP(&o.Cache.MinRows, "min-rows", "",
		"fail 'cache status' validation unless more than this many rows are present in the provider results")
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
	d.Add(&o.SkipValidation, `skip per-provider state validation before writing the DB`)
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

	d.Add(&o.Cache.Path, `path to the cache archive used by 'db-builder cache backup' and 'restore'`)
	d.Add(&o.Cache.DeleteExisting, `delete any existing provider data before restoring from the cache archive`)
	d.Add(&o.Cache.ResultsOnly, `archive only the provider 'results' directory (omit raw 'input' data)`)
	d.Add(&o.Cache.MinRows, `fail 'cache status' unless more than this many rows are present in the provider results`)
}
