// Package stats holds the log-linear latency histogram and window aggregation.
// The histogram must stay identical to the C++ implementation
// (perf/worker/histogram.hpp); both are tested against proto/testdata/histogram.json.
package stats

import (
	"fmt"
	"math/bits"
	"sort"
	"strconv"
)

const (
	LinearLimit = 64
	SubBuckets  = 32
	NumBuckets  = 64 + 35*32
)

// Index returns the bucket index for a latency in microseconds.
func Index(micros uint64) int {
	if micros < LinearLimit {
		return int(micros)
	}
	e := bits.Len64(micros) - 6
	idx := 64 + (e-1)*32 + int(micros>>uint(e)) - 32
	if idx >= NumBuckets {
		return NumBuckets - 1
	}
	return idx
}

// Midpoint returns a representative latency for a bucket.
func Midpoint(idx int) uint64 {
	if idx < LinearLimit {
		return uint64(idx)
	}
	k := idx - 64
	e := uint(k/32 + 1)
	m := uint64(k%32 + 32)
	return (m << e) + (uint64(1) << (e - 1))
}

// Hist is a dense histogram (nil/empty means no samples).
type Hist []uint64

// Add merges sparse (index,count) pairs.
func (h *Hist) AddSparse(idx []uint32, cnt []uint64) {
	if len(idx) == 0 {
		return
	}
	if len(*h) == 0 {
		*h = make(Hist, NumBuckets)
	}
	for i, ix := range idx {
		if int(ix) < NumBuckets && i < len(cnt) {
			(*h)[ix] += cnt[i]
		}
	}
}

// AddBucket adds count to one bucket.
func (h *Hist) AddBucket(idx int, count uint64) {
	if idx < 0 || idx >= NumBuckets || count == 0 {
		return
	}
	if len(*h) == 0 {
		*h = make(Hist, NumBuckets)
	}
	(*h)[idx] += count
}

// Merge adds o into h.
func (h *Hist) Merge(o Hist) {
	if len(o) == 0 {
		return
	}
	if len(*h) == 0 {
		*h = make(Hist, NumBuckets)
	}
	for i, c := range o {
		(*h)[i] += c
	}
}

func (h Hist) Total() uint64 {
	var t uint64
	for _, c := range h {
		t += c
	}
	return t
}

// Quantile returns the bucket midpoint at quantile q in [0,1]; 0 if empty.
func (h Hist) Quantile(q float64) uint64 {
	total := h.Total()
	if total == 0 {
		return 0
	}
	target := uint64(q*float64(total) + 0.999999999)
	if target < 1 {
		target = 1
	}
	var cum uint64
	for i, c := range h {
		cum += c
		if cum >= target {
			return Midpoint(i)
		}
	}
	return Midpoint(len(h) - 1)
}

// Max returns the midpoint of the highest non-empty bucket.
func (h Hist) Max() uint64 {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i] != 0 {
			return Midpoint(i)
		}
	}
	return 0
}

// Sparse returns the non-empty buckets in index order.
func (h Hist) Sparse() (idx []int, cnt []uint64) {
	for i, c := range h {
		if c != 0 {
			idx = append(idx, i)
			cnt = append(cnt, c)
		}
	}
	return
}

// MsNum renders a latency given in microseconds as milliseconds with 3 significant figures
// (no unit): 5772 -> "5.77", 10070 -> "10.1", 234 -> "0.234", 1234567 -> "1,235".
func MsNum(us float64) string {
	ms := us / 1000
	a := ms
	if a < 0 {
		a = -a
	}
	switch {
	case ms == 0:
		return "0"
	case a >= 1000:
		s := strconv.FormatInt(int64(ms+0.5), 10)
		var out []byte
		for i, c := range []byte(s) {
			if i > 0 && (len(s)-i)%3 == 0 {
				out = append(out, ',')
			}
			out = append(out, c)
		}
		return string(out)
	case a >= 100:
		return fmt.Sprintf("%.0f", ms)
	case a >= 10:
		return fmt.Sprintf("%.1f", ms)
	case a >= 1:
		return fmt.Sprintf("%.2f", ms)
	case a >= 0.1:
		return fmt.Sprintf("%.3f", ms)
	default:
		return fmt.Sprintf("%.4f", ms)
	}
}

// Ms is MsNum with a unit suffix.
func Ms(us float64) string { return MsNum(us) + "ms" }

// Summary stats (min max avg median p90 p95 p99 dev%) over a sample series.
type Summary struct {
	N                     int
	Min, Max, Avg, Median float64
	P90, P95, P99         float64
	DevPct                float64 // % of samples deviating from median by > deviation%
}

// Summarize computes Summary; deviation is a percentage (e.g. 10).
func Summarize(vals []float64, deviation float64) Summary {
	s := Summary{N: len(vals)}
	if len(vals) == 0 {
		return s
	}
	v := append([]float64(nil), vals...)
	sort.Float64s(v)
	var sum float64
	for _, x := range v {
		sum += x
	}
	s.Min, s.Max, s.Avg = v[0], v[len(v)-1], sum/float64(len(v))
	s.Median = pct(v, 50)
	s.P90, s.P95, s.P99 = pct(v, 90), pct(v, 95), pct(v, 99)
	if s.Median != 0 {
		bad := 0
		for _, x := range v {
			d := x - s.Median
			if d < 0 {
				d = -d
			}
			if d/s.Median*100 > deviation {
				bad++
			}
		}
		s.DevPct = float64(bad) / float64(len(v)) * 100
	}
	return s
}

// pct is the linear-interpolated percentile of a sorted slice.
func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := p / 100 * float64(len(sorted)-1)
	lo := int(pos)
	if lo >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(lo)
	return sorted[lo] + (sorted[lo+1]-sorted[lo])*frac
}
