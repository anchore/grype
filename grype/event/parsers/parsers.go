package parsers

import (
	"fmt"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/event/monitor"
)

type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field='%v': '%+v'", string(e.Type), e.Field, e.Value)
}

func newPayloadErr(t partybus.EventType, field string, value interface{}) error {
	return &ErrBadPayload{
		Type:  t,
		Field: field,
		Value: value,
	}
}

func checkEventType(actual, expected partybus.EventType) error {
	if actual != expected {
		return newPayloadErr(expected, "Type", actual)
	}
	return nil
}

func ParseUpdateVulnerabilityDatabase(e partybus.Event) (progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.UpdateVulnerabilityDatabase); err != nil {
		return nil, err
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return prog, nil
}

func ParseVulnerabilityScanningStarted(e partybus.Event) (*monitor.Matching, error) {
	if err := checkEventType(e.Type, event.VulnerabilityScanningStarted); err != nil {
		return nil, err
	}

	mon, ok := e.Value.(monitor.Matching)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &mon, nil
}

func ParseDatabaseDiffingStarted(e partybus.Event) (*monitor.DBDiff, error) {
	if err := checkEventType(e.Type, event.DatabaseDiffingStarted); err != nil {
		return nil, err
	}

	mon, ok := e.Value.(monitor.DBDiff)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &mon, nil
}

type UpdateCheck struct {
	New     string
	Current string
}

func ParseCLIAppUpdateAvailable(e partybus.Event) (*UpdateCheck, error) {
	if err := checkEventType(e.Type, event.CLIAppUpdateAvailable); err != nil {
		return nil, err
	}

	updateCheck, ok := e.Value.(UpdateCheck)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &updateCheck, nil
}

func ParseCLIReport(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLIReport); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	report, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, report, nil
}

func ParseCLINotification(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLINotification); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	notification, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, notification, nil
}
