package external

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anchore/grype/internal/redact"
	"github.com/google/shlex"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

var _ provider.Provider = (*pvdr)(nil)

type Config struct {
	Cmd     string            `yaml:"cmd" json:"cmd" mapstructure:"cmd"`
	ExecDir string            `yaml:"dir,omitempty" json:"dir,omitempty" mapstructure:"dir"`
	State   string            `yaml:"state" json:"state" mapstructure:"state"`
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty" mapstructure:"env"`
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

type pvdr struct {
	id   provider.Identifier
	cfg  Config
	root string
}

func NewProvider(root string, id provider.Identifier, cfg Config) provider.Provider {
	return &pvdr{
		id:   id,
		cfg:  cfg,
		root: root,
	}
}

func (p pvdr) ID() provider.Identifier {
	return p.id
}

func (p pvdr) State() (*provider.State, error) {
	return provider.ReadState(filepath.Join(p.root, p.cfg.State))
}

func (p pvdr) Update(ctx context.Context) error {
	if err := run(ctx, p.cfg.Cmd, p.cfg.ExecDir, p.ID().Name, p.cfg.Env); err != nil {
		return fmt.Errorf("failed to pull data from %q provider: %w", p.id.Name, err)
	}
	return nil
}

func run(ctx context.Context, cmd, dir, name string, env map[string]string) error {
	log.WithFields("provider", name, "dir", dir).Tracef("running external provider: %q", cmd)

	parsedArgs, err := shlex.Split(cmd)
	if err != nil {
		return fmt.Errorf("unable to parse shell arguments %q: %w", cmd, err)
	}

	if len(parsedArgs) == 0 {
		return fmt.Errorf("no command specified")
	}
	cmdStr := parsedArgs[0]
	var args []string
	if len(parsedArgs) > 1 {
		args = parsedArgs[1:]
	}
	cmdObj := exec.CommandContext(ctx, cmdStr, args...)
	cmdObj.Dir = dir
	cmdObj.Env = append(cmdObj.Env, envMapToSlice(env)...)

	cmdObj.Stdout = newLogWriter(name)
	cmdObj.Stderr = newLogWriter(name)

	if err := cmdObj.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok { //nolint: errorlint
			return fmt.Errorf("command failed: %d", exitError.ExitCode())
		}
		return err
	}

	return nil
}

func envMapToSlice(env map[string]string) (envList []string) {
	for key, val := range env {
		if key == "" {
			continue
		}
		if strings.HasPrefix(val, "$") {
			val = os.Getenv(val[1:])
			// for safety, assume that all values from environment variables are sensitive
			redact.Add(val)
		}
		envList = append(envList, fmt.Sprintf("%s=%s", key, val))
	}
	return
}
