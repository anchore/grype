package cli

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ConcurrentAccess(t *testing.T) {
	wg := sync.WaitGroup{}
	iterations := 10
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		go func() {
			defer wg.Done()
			cmd, _, _ := runGrype(t, nil, "alpine:3.15", "-vv")
			require.Equal(t, 0, cmd.ProcessState.ExitCode())
		}()
	}
	wg.Wait()
}
