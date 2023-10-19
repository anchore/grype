package ui

import (
	"reflect"
	"sync"
	"testing"
	"unsafe"

	tea "github.com/charmbracelet/bubbletea"
)

func runModel(t testing.TB, m tea.Model, iterations int, message tea.Msg, wgs ...*sync.WaitGroup) string {
	t.Helper()
	if iterations == 0 {
		iterations = 1
	}
	m.Init()
	var cmd tea.Cmd = func() tea.Msg {
		return message
	}

	for _, wg := range wgs {
		if wg != nil {
			wg.Wait()
		}
	}

	for i := 0; cmd != nil && i < iterations; i++ {
		msgs := flatten(cmd())
		var nextCmds []tea.Cmd
		var next tea.Cmd
		for _, msg := range msgs {
			t.Logf("Message: %+v %+v\n", reflect.TypeOf(msg), msg)
			m, next = m.Update(msg)
			nextCmds = append(nextCmds, next)
		}
		cmd = tea.Batch(nextCmds...)
	}
	return m.View()
}

func flatten(p tea.Msg) (msgs []tea.Msg) {
	if reflect.TypeOf(p).Name() == "batchMsg" {
		partials := extractBatchMessages(p)
		for _, m := range partials {
			msgs = append(msgs, flatten(m)...)
		}
	} else {
		msgs = []tea.Msg{p}
	}
	return msgs
}

func extractBatchMessages(m tea.Msg) (ret []tea.Msg) {
	sliceMsgType := reflect.SliceOf(reflect.TypeOf(tea.Cmd(nil)))
	value := reflect.ValueOf(m) // note: this is technically unaddressable

	// make our own instance that is addressable
	valueCopy := reflect.New(value.Type()).Elem()
	valueCopy.Set(value)

	cmds := reflect.NewAt(sliceMsgType, unsafe.Pointer(valueCopy.UnsafeAddr())).Elem()
	for i := 0; i < cmds.Len(); i++ {
		item := cmds.Index(i)
		r := item.Call(nil)
		ret = append(ret, r[0].Interface().(tea.Msg))
	}
	return ret
}
