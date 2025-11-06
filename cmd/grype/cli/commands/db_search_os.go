package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
)

type dbSearchOSOptions struct {
	Output                  string `yaml:"output" json:"output"`
	Name                    string `yaml:"name" json:"name"`
	Version                 string `yaml:"version" json:"version"`
	Channel                 string `yaml:"channel" json:"channel"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbSearchOSOptions)(nil)

func (d *dbSearchOSOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[table, json])")
	flags.StringVarP(&d.Name, "name", "n", "filter by OS name or release ID (e.g., 'ubuntu', 'rhel', 'ol')")
	flags.StringVarP(&d.Version, "version", "", "filter by OS version or codename (e.g., '20.04', 'focal', '8.1+eus')")
	flags.StringVarP(&d.Channel, "channel", "", "filter by channel (e.g., 'eus')")
}

// applyArgs parses command arguments and applies them to search options
func (o *dbSearchOSOptions) applyArgs(args []string) error {
	for _, arg := range args {
		if arg == "" {
			continue
		}

		var name, versionOrCodename, channel string

		// parse: name[@version_or_codename[+channel]]
		// or:    version_or_codename[+channel]
		// or:    name
		if strings.Contains(arg, "@") {
			parts := strings.SplitN(arg, "@", 2)
			name = parts[0]
			if len(parts) == 2 {
				versionOrCodename = parts[1]
			}
		} else {
			versionOrCodename = arg
		}

		// check for + separator in version/codename part
		if versionOrCodename != "" && strings.Contains(versionOrCodename, "+") {
			parts := strings.SplitN(versionOrCodename, "+", 2)
			versionOrCodename = parts[0]
			if len(parts) == 2 {
				channel = parts[1]
			}
		}

		// apply parsed values
		// name is explicit when @ is present
		if name != "" {
			if o.Name != "" && o.Name != name {
				return fmt.Errorf("conflicting OS name specified: '%s' and '%s'", o.Name, name)
			}
			o.Name = name
		}

		// version/codename could be either, or could be a name if no @ was present
		if versionOrCodename != "" {
			// if it looks like a version (contains .), treat as version
			// otherwise, it could be name, version, or codename
			if strings.Contains(versionOrCodename, ".") {
				// likely a version number
				if o.Version != "" && o.Version != versionOrCodename {
					return fmt.Errorf("conflicting version specified: '%s' and '%s'", o.Version, versionOrCodename)
				}
				o.Version = versionOrCodename
			} else if name != "" {
				// we had name@ prefix, so this must be version/codename
				if o.Version != "" && o.Version != versionOrCodename {
					return fmt.Errorf("conflicting version specified: '%s' and '%s'", o.Version, versionOrCodename)
				}
				o.Version = versionOrCodename
			} else {
				// ambiguous: could be name, version, or codename
				// if we don't have a name yet, try it as name
				// otherwise, try it as version
				if o.Name == "" {
					o.Name = versionOrCodename
				} else if o.Version == "" {
					o.Version = versionOrCodename
				} else {
					return fmt.Errorf("ambiguous argument '%s': already have name '%s' and version '%s'", versionOrCodename, o.Name, o.Version)
				}
			}
		}

		// channel is explicit when + is present
		if channel != "" {
			if o.Channel != "" && !strings.EqualFold(o.Channel, channel) {
				return fmt.Errorf("conflicting channel specified: '%s' and '%s'", o.Channel, channel)
			}
			o.Channel = channel
		}
	}

	return nil
}

func DBSearchOS(app clio.Application) *cobra.Command {
	opts := &dbSearchOSOptions{
		Output:          tableOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "os [NAME[@VERSION[+CHANNEL]]]...",
		Short: "Search operating systems in the database",
		Example: `
  List all operating systems:

    $ grype db search os

  Search by name:

    $ grype db search os ubuntu
    $ grype db search os ol        # Oracle Linux by release ID

  Search by name and version:

    $ grype db search os ubuntu@20.04
    $ grype db search os ubuntu 20.04

  Search by codename:

    $ grype db search os focal
    $ grype db search os ubuntu@focal

  Search with channel:

    $ grype db search os rhel@8.1+eus
    $ grype db search os 8.1+eus
    $ grype db search os focal+eus

  Multiple arguments (accumulated):

    $ grype db search os ubuntu focal

  Using flags (optional):

    $ grype db search os --name ubuntu --version focal --channel eus`,
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.applyArgs(args); err != nil {
					return err
				}
			}
			return runDBSearchOS(opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbSearchOSOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBSearchOS(opts *dbSearchOSOptions) error {
	// parse and validate options
	parsedOpts, err := parseSearchOptions(*opts)
	if err != nil {
		return err
	}

	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := c.Reader()
	if err != nil {
		return fmt.Errorf("unable to get reader: %w", err)
	}

	// leverage store search when we have specific criteria
	var osModels []v6.OperatingSystem
	if parsedOpts.canUseStoreSearch() {
		osModels, err = reader.GetOperatingSystems(parsedOpts.toOSSpecifier())
		if err != nil {
			return fmt.Errorf("unable to get operating systems: %w", err)
		}
	} else {
		osModels, err = reader.AllOperatingSystems()
		if err != nil {
			return fmt.Errorf("unable to get operating systems: %w", err)
		}
	}

	// get the provider associations for all operating systems
	osProviders, err := reader.GetOperatingSystemProviders()
	if err != nil {
		return fmt.Errorf("unable to get providers for operating systems: %w", err)
	}

	// convert and group
	allOS := toOperatingSystems(osModels, osProviders)

	// apply additional filters if needed
	filtered := filterOperatingSystems(allOS, parsedOpts)

	sb := &strings.Builder{}

	switch opts.Output {
	case tableOutputFormat, textOutputFormat:
		err = displayDBOSTable(filtered, sb)
		if err != nil {
			return err
		}
	case jsonOutputFormat:
		err = displayDBOSJSON(filtered, sb)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}
	bus.Report(sb.String())

	return nil
}

// parsedSearchOptions holds the parsed and validated search criteria
type parsedSearchOptions struct {
	name    string
	version string
	channel string
}

// parseSearchOptions parses and validates the user-provided search options
func parseSearchOptions(opts dbSearchOSOptions) (parsedSearchOptions, error) {
	parsed := parsedSearchOptions{
		name:    opts.Name,
		version: opts.Version,
		channel: opts.Channel,
	}

	// parse name@version syntax if provided
	if strings.Contains(parsed.name, "@") {
		parts := strings.SplitN(parsed.name, "@", 2)
		parsed.name = parts[0]
		if len(parts) == 2 {
			if parsed.version != "" && parsed.version != parts[1] {
				return parsed, fmt.Errorf("conflicting version specified: '@%s' in name and '--version %s'", parts[1], parsed.version)
			}
			parsed.version = parts[1]
		}
	}

	// parse version string for channel suffix (e.g., "8.1+eus")
	if parsed.version != "" {
		version := parsed.version
		var channelFromVersion string

		if strings.Contains(version, "+") {
			parts := strings.SplitN(version, "+", 2)
			version = parts[0]
			if len(parts) == 2 {
				channelFromVersion = parts[1]
			}
		}

		// validate channel conflicts
		if channelFromVersion != "" && parsed.channel != "" {
			if !strings.EqualFold(channelFromVersion, parsed.channel) {
				return parsed, fmt.Errorf("conflicting channel specified: '+%s' in version and '--channel %s'", channelFromVersion, parsed.channel)
			}
		}

		// use channel from version if not already set
		if channelFromVersion != "" {
			parsed.channel = channelFromVersion
		}

		parsed.version = version
	}

	return parsed, nil
}

// canUseStoreSearch returns true if we have enough criteria to use the store's GetOperatingSystems
func (p parsedSearchOptions) canUseStoreSearch() bool {
	// the store requires at least name or version (as LabelVersion)
	return p.name != "" || p.version != ""
}

// toOSSpecifier converts parsed options to a v6.OSSpecifier for store queries
func (p parsedSearchOptions) toOSSpecifier() v6.OSSpecifier {
	spec := v6.OSSpecifier{
		Name:         p.name,
		LabelVersion: p.version,
		Channel:      p.channel,
	}

	// try to parse version as major.minor if it looks numeric
	if p.version != "" && strings.Contains(p.version, ".") {
		parts := strings.SplitN(p.version, ".", 2)
		if len(parts) == 2 {
			spec.MajorVersion = parts[0]
			spec.MinorVersion = parts[1]
			spec.LabelVersion = "" // clear label version when we have numeric version
		}
	}

	return spec
}

// filterOperatingSystems applies user-specified filters to the OS list
func filterOperatingSystems(osList []operatingSystem, opts parsedSearchOptions) []operatingSystem {
	nameFilter := strings.ToLower(opts.name)
	versionFilter := strings.ToLower(opts.version)
	channelFilter := strings.ToLower(opts.channel)

	// if no filters are specified, return all
	if nameFilter == "" && versionFilter == "" && channelFilter == "" {
		return osList
	}

	var filtered []operatingSystem
	for _, os := range osList {
		// skip if filters were already applied by store search
		// (this function only handles additional filtering not done by store)
		if nameFilter != "" && !strings.EqualFold(os.Name, nameFilter) {
			continue
		}

		if channelFilter != "" && !strings.EqualFold(os.Channel, channelFilter) {
			continue
		}

		// apply version filter (matches version value or codename)
		if versionFilter != "" {
			var matchedVersions []osVersion
			for _, v := range os.Versions {
				// match against either version value or codename
				if strings.EqualFold(v.Value, versionFilter) || strings.EqualFold(v.Codename, versionFilter) {
					matchedVersions = append(matchedVersions, v)
				}
			}

			// if no versions matched, skip this OS group
			if len(matchedVersions) == 0 {
				continue
			}

			// create a new OS entry with only the matched versions
			filteredOS := os
			filteredOS.Versions = matchedVersions
			filtered = append(filtered, filteredOS)
		} else {
			// no version filter, include all versions
			filtered = append(filtered, os)
		}
	}

	return filtered
}

type osVersion struct {
	Value    string `json:"value"`
	Codename string `json:"codename,omitempty"`
}

type operatingSystem struct {
	Name      string      `json:"name"`
	Versions  []osVersion `json:"versions"`
	ReleaseID string      `json:"releaseId,omitempty"`
	Channel   string      `json:"channel,omitempty"`
	Provider  string      `json:"provider"`
}

// formatVersion formats the version string for display, adding leading zeros to Ubuntu minor versions when needed
// and stripping the channel suffix since it's shown separately
func formatVersion(os v6.OperatingSystem) string {
	version := os.Version()

	// strip the channel suffix (e.g., "+eus") since it's redundant with the channel column
	if os.Channel != "" {
		suffix := "+" + os.Channel
		version = strings.TrimSuffix(version, suffix)
	}

	// for Ubuntu, pad single-digit minor versions with a leading zero
	if strings.EqualFold(os.Name, "ubuntu") && os.MajorVersion != "" && os.MinorVersion != "" && len(os.MinorVersion) == 1 {
		// reconstruct the version with padded minor version
		paddedMinor := "0" + os.MinorVersion
		return fmt.Sprintf("%s.%s", os.MajorVersion, paddedMinor)
	}

	return version
}

func toOperatingSystems(osModels []v6.OperatingSystem, osProviders map[v6.ID][]string) []operatingSystem {
	// group OSes by (name, channel, provider) and collect versions with codenames
	type groupKey struct {
		name      string
		channel   string
		provider  string
		releaseID string
	}

	groups := make(map[groupKey][]osVersion)

	for _, os := range osModels {
		providers := osProviders[os.ID]
		if providers == nil {
			providers = []string{}
		}

		version := formatVersion(os)
		provider := strings.Join(providers, ", ")

		key := groupKey{
			name:      os.Name,
			channel:   os.Channel,
			provider:  provider,
			releaseID: os.ReleaseID,
		}

		groups[key] = append(groups[key], osVersion{
			Value:    version,
			Codename: os.Codename,
		})
	}

	// convert groups to result slice
	var res []operatingSystem
	for key, versions := range groups {
		res = append(res, operatingSystem{
			Name:      key.name,
			Versions:  versions,
			ReleaseID: key.releaseID,
			Channel:   key.channel,
			Provider:  key.provider,
		})
	}

	// sort by name, then channel
	sort.Slice(res, func(i, j int) bool {
		if res[i].Name != res[j].Name {
			return res[i].Name < res[j].Name
		}
		return res[i].Channel < res[j].Channel
	})

	return res
}

// wrapText wraps text at word boundaries to fit within maxWidth characters per line
func wrapText(text string, maxWidth int) string {
	if len(text) <= maxWidth {
		return text
	}

	var lines []string
	var currentLine string

	words := strings.Split(text, " ")
	for _, word := range words {
		// if adding this word would exceed maxWidth, start a new line
		if currentLine != "" && len(currentLine)+1+len(word) > maxWidth {
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			if currentLine != "" {
				currentLine += " " + word
			} else {
				currentLine = word
			}
		}
	}

	// add the last line
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return strings.Join(lines, "\n")
}

func displayDBOSTable(operatingSystems []operatingSystem, output io.Writer) error {
	rows := [][]string{}
	for _, os := range operatingSystems {
		// extract just the version values for display
		var versionValues []string
		for _, v := range os.Versions {
			versionValues = append(versionValues, v.Value)
		}
		versions := strings.Join(versionValues, ", ")

		// wrap versions if they exceed 50 characters
		versions = wrapText(versions, 50)

		channel := os.Channel
		if channel == "" {
			channel = "-"
		}
		rows = append(rows, []string{os.Name, versions, channel, os.Provider})
	}

	table := newTable(output, []string{"Name", "Versions", "Channel", "Provider"})

	if err := table.Bulk(rows); err != nil {
		return fmt.Errorf("failed to add table rows: %w", err)
	}
	return table.Render()
}

func displayDBOSJSON(operatingSystems []operatingSystem, output io.Writer) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	err := encoder.Encode(operatingSystems)
	if err != nil {
		return fmt.Errorf("cannot display json: %w", err)
	}
	return nil
}
