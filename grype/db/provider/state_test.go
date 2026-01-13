package provider

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_earliestTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		states  []State
		want    time.Time
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "happy path",
			states: []State{
				{
					Timestamp: time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC),
				},
				{
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Timestamp: time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC),
				},
			},
			want: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "empty states",
			states:  []State{},
			want:    time.Time{},
			wantErr: requireErrorContains("cannot find earliest timestamp: no states provided"),
		},
		{
			name: "single state",
			states: []State{
				{
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			want: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "single state, but it's nvd",
			states: []State{
				{
					Provider:  "nvd",
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			want: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "all states have provider nvd",
			states: []State{
				{
					Provider:  "nvd",
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Provider:  "nvd",
					Timestamp: time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC),
				},
			},
			want:    time.Time{},
			wantErr: requireErrorContains("unable to determine earliest timestamp"),
		},
		{
			name: "mix of nvd and non-nvd providers",
			states: []State{
				{
					Provider:  "nvd",
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Provider:  "other",
					Timestamp: time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC),
				},
				{
					Provider:  "other",
					Timestamp: time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC),
				},
			},
			want: time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "timestamps are the same",
			states: []State{
				{
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			want: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := States(tt.states).EarliestTimestamp()
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("earliestTimestamp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func requireErrorContains(text string) require.ErrorAssertionFunc {
	return func(t require.TestingT, err error, msgAndArgs ...interface{}) {
		require.Error(t, err, msgAndArgs...)
		require.Contains(t, err.Error(), text, msgAndArgs...)
	}
}
