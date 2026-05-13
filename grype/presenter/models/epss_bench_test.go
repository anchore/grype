package models

import (
	"sort"
	"testing"
)

// --- two implementations under test ---

// current: full sort to find maximum
func epssPercentileCurrent(es []EPSS) float64 {
	switch len(es) {
	case 0:
		return 0.0
	case 1:
		return es[0].Percentile
	}
	sort.Slice(es, func(i, j int) bool {
		return es[i].Percentile > es[j].Percentile
	})
	return es[0].Percentile
}

// proposed: linear scan to find maximum
func epssPercentileLinear(es []EPSS) float64 {
	if len(es) == 0 {
		return 0.0
	}
	max := es[0].Percentile
	for _, e := range es[1:] {
		if e.Percentile > max {
			max = e.Percentile
		}
	}
	return max
}

// --- representative inputs ---

var benchEPSSSmall = []EPSS{
	{Percentile: 0.50},
	{Percentile: 0.95},
	{Percentile: 0.75},
}

var benchEPSSLarge = func() []EPSS {
	out := make([]EPSS, 100)
	for i := range out {
		out[i] = EPSS{Percentile: float64(i) / 100.0}
	}
	return out
}()

// --- benchmarks ---

func BenchmarkEPSSPercentileCurrentSmall(b *testing.B) {
	b.ReportAllocs()
	var sink float64
	for b.Loop() {
		input := make([]EPSS, len(benchEPSSSmall))
		copy(input, benchEPSSSmall)
		sink += epssPercentileCurrent(input)
	}
	_ = sink
}

func BenchmarkEPSSPercentileLinearSmall(b *testing.B) {
	b.ReportAllocs()
	var sink float64
	for b.Loop() {
		sink += epssPercentileLinear(benchEPSSSmall)
	}
	_ = sink
}

func BenchmarkEPSSPercentileCurrentLarge(b *testing.B) {
	b.ReportAllocs()
	var sink float64
	for b.Loop() {
		input := make([]EPSS, len(benchEPSSLarge))
		copy(input, benchEPSSLarge)
		sink += epssPercentileCurrent(input)
	}
	_ = sink
}

func BenchmarkEPSSPercentileLinearLarge(b *testing.B) {
	b.ReportAllocs()
	var sink float64
	for b.Loop() {
		sink += epssPercentileLinear(benchEPSSLarge)
	}
	_ = sink
}
