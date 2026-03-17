package provider

import (
	"path/filepath"
)

type Workspace struct {
	Root string
	Name string
}

func NewWorkspace(root, name string) Workspace {
	return Workspace{
		Root: root,
		Name: name,
	}
}

func NewWorkspaceFromExisting(workspacePath string) Workspace {
	return Workspace{
		Root: filepath.Dir(workspacePath),
		Name: filepath.Base(workspacePath),
	}
}

func (w Workspace) Path() string {
	return filepath.Join(w.Root, w.Name)
}

func (w Workspace) StatePath() string {
	return filepath.Join(w.Path(), "metadata.json")
}

func (w Workspace) InputPath() string {
	return filepath.Join(w.Path(), "input")
}

func (w Workspace) ResultsPath() string {
	return filepath.Join(w.Path(), "results")
}

func (w Workspace) ReadState() (*State, error) {
	return ReadState(w.StatePath())
}
