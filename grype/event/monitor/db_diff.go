package monitor

import "github.com/wagoodman/go-progress"

type DBDiff struct {
	Stager                progress.Stager
	StageProgress         progress.Progressable
	DifferencesDiscovered progress.Monitorable
}
