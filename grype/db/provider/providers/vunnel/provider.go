package vunnel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anchore/grype/internal/redact"
	"github.com/google/shlex"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/providers/external"
	"github.com/anchore/grype/internal/log"
)

type Config struct {
	Config           string            `yaml:"config" json:"config" mapstructure:"config"`
	Executor         string            `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerImage      string            `yaml:"docker-image" json:"docker-image" mapstructure:"docker-image"`
	DockerTag        string            `yaml:"docker-tag" json:"docker-tag" mapstructure:"docker-tag"`
	GenerateConfigs  bool              `yaml:"generate-configs" json:"generate-configs" mapstructure:"generate-configs"`
	ExcludeProviders []string          `yaml:"exclude-providers" json:"exclude-providers" mapstructure:"exclude-providers"`
	Env              map[string]string `yaml:"env,omitempty" json:"env,omitempty" mapstructure:"env"`
}

func (c Config) Redact() {
	if c.Env == nil {
		return
	}
	for _, v := range c.Env {
		// note: we don't know which env vars are sensitive, so we assume all are
		redact.Add(v)
	}
}

func NewProvider(root string, id provider.Identifier, cfg Config) provider.Provider {
	return external.NewProvider(root, id,
		external.Config{
			Cmd:   getRunCommand(root, id, cfg),
			State: fmt.Sprintf("%s/metadata.json", id.Name),
			Env:   cfg.Env,
		},
	)
}

func getRunCommand(root string, id provider.Identifier, cfg Config) string {
	switch cfg.Executor {
	case "docker", "podman":
		dataRootCtr := root
		if !strings.HasPrefix(root, "/") {
			dataRootCtr = strings.TrimPrefix(root, "./")
		}

		dataRootHost, err := filepath.Abs(root)
		if err != nil {
			log.WithFields("error", err).Warn("unable to get absolute path for provider root directory, using relative path")
			dataRootHost = root
		}

		var cfgVol string
		if _, err := os.Stat(".vunnel.yaml"); !os.IsNotExist(err) {
			cwd, err := os.Getwd()
			if err != nil {
				log.WithFields("error", err, "provider", id.Name).Warn("unable to get current working directory, ignoring vunnel config")
			} else {
				cfgVol = fmt.Sprintf("-v %s/.vunnel.yaml:/.vunnel.yaml", cwd)
			}
		}

		var envStr string
		if cfg.Env != nil {
			for k, v := range cfg.Env {
				if strings.HasPrefix(v, "$") {
					v = os.Getenv(v[1:])
					// for safety, assume that all values from environment variables are sensitive
					redact.Add(v)
				}
				envStr += fmt.Sprintf("-e %s=%s ", k, v)
			}
		}

		return fmt.Sprintf("%s run --rm -t -v %s:/%s %s %s %s:%s run %s", cfg.Executor, dataRootHost, dataRootCtr, cfgVol, envStr, cfg.DockerImage, cfg.DockerTag, id.Name)
	}

	var cfgSection string
	if cfg.Config != "" {
		cfgSection = fmt.Sprintf("-c %s", cfg.Config)
	}

	return fmt.Sprintf("vunnel %s run %s", cfgSection, id.Name)
}

func getListCommand(root string, cfg Config) string {
	switch cfg.Executor {
	case "docker", "podman":
		dataRootCtr := root
		if !strings.HasPrefix(root, "/") {
			dataRootCtr = strings.TrimPrefix(root, "./")
		}

		dataRootHost, err := filepath.Abs(root)
		if err != nil {
			log.WithFields("error", err).Warn("unable to get absolute path for provider root directory, using relative path")
			dataRootHost = root
		}

		var cfgVol string
		if _, err := os.Stat(".vunnel.yaml"); !os.IsNotExist(err) {
			cwd, err := os.Getwd()
			if err != nil {
				log.WithFields("error", err).Warn("unable to get current working directory, ignoring vunnel config")
			} else {
				cfgVol = fmt.Sprintf("-v %s/.vunnel.yaml:/.vunnel.yaml", cwd)
			}
		}

		var envStr string
		if cfg.Env != nil {
			for k, v := range cfg.Env {
				if strings.HasPrefix(v, "$") {
					v = os.Getenv(v[1:])
					// for safety, assume that all values from environment variables are sensitive
					redact.Add(v)
				}
				envStr += fmt.Sprintf("-e %s=%s ", k, v)
			}
		}

		return fmt.Sprintf("%s run --rm -t -v %s:/%s %s %s %s:%s list", cfg.Executor, dataRootHost, dataRootCtr, cfgVol, envStr, cfg.DockerImage, cfg.DockerTag)
	}

	var cfgSection string
	if cfg.Config != "" {
		cfgSection = fmt.Sprintf("-c %s", cfg.Config)
	}

	return fmt.Sprintf("vunnel %s list", cfgSection)
}

func GenerateConfigs(root string, cfg Config) ([]provider.Config, error) {
	cmdStr := getListCommand(root, cfg)
	cmdList, err := shlex.Split(cmdStr)
	if err != nil {
		return nil, err
	}
	cmd, args := cmdList[0], cmdList[1:]

	cmdObj := exec.Command(cmd, args...)
	sb := strings.Builder{}
	cmdObj.Stderr = &sb
	out, err := cmdObj.Output()
	if err != nil {
		if sb.Len() > 0 {
			log.Errorf("vunnel list failed: %s", sb.String())
		}
		return nil, fmt.Errorf("unable to execute vunnel list: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	excludeSet := strset.New(cfg.ExcludeProviders...)

	var cfgs []provider.Config
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, " ") || strings.Contains(line, ":") || strings.Contains(line, "[") {
			log.WithFields("value", line).Trace("provider name appears to be invalid, skipping")
			continue
		}

		if excludeSet.Has(line) {
			log.WithFields("provider", line).Trace("skipping config")
			continue
		}
		log.WithFields("provider", line).Trace("including config")
		cfgs = append(cfgs, provider.Config{
			Identifier: provider.Identifier{
				Name: line,
				Kind: provider.VunnelKind,
			},
		})
	}

	return cfgs, nil
}
