package commands

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lotsaParallel = 100

func Test_lotsaLotsaParallel(t *testing.T) {
	funcs := []func() error{}
	for i := 0; i < lotsaParallel; i++ {
		funcs = append(funcs, func() error {
			Test_lotsaParallel(t)
			return nil
		})
	}
	err := parallel(funcs...)
	require.NoError(t, err)
}

func Test_lotsaParallel(t *testing.T) {
	for i := 0; i < lotsaParallel; i++ {
		Test_parallel(t)
	}
}

// Test_parallel tests the parallel function by executing a set of functions that can only execute in a specific
// order if they are actually running in parallel.
func Test_parallel(t *testing.T) {
	count := atomic.Int32{}
	count.Store(0)

	wg1 := sync.WaitGroup{}
	wg1.Add(1)

	wg2 := sync.WaitGroup{}
	wg2.Add(1)

	wg3 := sync.WaitGroup{}
	wg3.Add(1)

	err1 := fmt.Errorf("error-1")
	err2 := fmt.Errorf("error-2")
	err3 := fmt.Errorf("error-3")

	order := ""

	got := parallel(
		func() error {
			wg1.Wait()
			count.Add(1)
			order = order + "_0"
			return nil
		},
		func() error {
			wg3.Wait()
			defer wg2.Done()
			count.Add(10)
			order = order + "_1"
			return err1
		},
		func() error {
			wg2.Wait()
			defer wg1.Done()
			count.Add(100)
			order = order + "_2"
			return err2
		},
		func() error {
			defer wg3.Done()
			count.Add(1000)
			order = order + "_3"
			return err3
		},
	)
	require.Equal(t, int32(1111), count.Load())
	require.Equal(t, "_3_1_2_0", order)

	errs := got.(*multierror.Error).Errors

	// cannot check equality to a slice with err1,2,3 because the functions above are running in parallel, for example:
	// after func()#4 returns and the `wg3.Done()` has executed, the thread could immediately pause
	// and the remaining functions execute first and err3 becomes the last in the list instead of the first
	require.Contains(t, errs, err1)
	require.Contains(t, errs, err2)
	require.Contains(t, errs, err3)
}

func Test_parallelMapped(t *testing.T) {
	err0 := fmt.Errorf("error-0")
	err1 := fmt.Errorf("error-1")
	err2 := fmt.Errorf("error-2")

	tests := []struct {
		name     string
		funcs    []func() error
		expected map[int]error
	}{
		{
			name: "basic",
			funcs: []func() error{
				func() error {
					return nil
				},
				func() error {
					return err1
				},
				func() error {
					return nil
				},
				func() error {
					return err2
				},
			},
			expected: map[int]error{
				1: err1,
				3: err2,
			},
		},
		{
			name: "no errors",
			funcs: []func() error{
				func() error {
					return nil
				},
				func() error {
					return nil
				},
			},
			expected: map[int]error{},
		},
		{
			name: "all errors",
			funcs: []func() error{
				func() error {
					return err0
				},
				func() error {
					return err1
				},
				func() error {
					return err2
				},
			},
			expected: map[int]error{
				0: err0,
				1: err1,
				2: err2,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parallelMapped(test.funcs...)
			require.Equal(t, test.expected, got)
		})
	}
}

func TestTrimmingWriter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes trailing spaces",
			input:    "line with trailing spaces   \nline with no trailing spaces\n",
			expected: "line with trailing spaces\nline with no trailing spaces\n",
		},
		{
			name:     "handles multiple spaces and tabs",
			input:    "line with tabs\t\t\t\nline with spaces    \t \t\t\n",
			expected: "line with tabs\nline with spaces\n",
		},
		{
			name:     "handles embedded whitespace",
			input:    "line one with spaces   and tabs\t\t\nnext line\t\n",
			expected: "line one with spaces   and tabs\nnext line\n",
		},
		{
			name:     "handles empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "handles only spaces and tabs",
			input:    "   \t\t\n   \t \t\n",
			expected: "\n\n",
		},
		{
			name:     "handles single character input",
			input:    "a",
			expected: "a",
		},
		{
			name:     "handles input ending without newline",
			input:    "line without newline  ",
			expected: "line without newline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			writer := newTrimmingWriter(&output)

			n, err := writer.Write([]byte(tt.input))
			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)
			assert.Equal(t, tt.expected, output.String())
		})
	}
}
