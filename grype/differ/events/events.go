package events

import "github.com/wagoodman/go-progress"

type Monitor struct {
	RowsProcessed         progress.Monitorable
	DifferencesDiscovered progress.Monitorable
}
