package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"kvrgw-perf/internal/stats"
)

// perRoleStatRoles are the roles in the per-role table, in print order. Only storage and log
// do real disk I/O, so only they get a disk busy row.
var perRoleStatRoles = []struct {
	name string
	disk bool
}{{"storage", true}, {"log", true}, {"grv_proxy", false}, {"commit_proxy", false}, {"resolver", false}}

// windowMean is the mean of the samples in (win[0], win[1]]; ok is false if there are none.
func windowMean(s []sample, win [2]int64) (float64, bool) {
	var acc float64
	n := 0
	for _, x := range s {
		if x.ts > win[0] && x.ts <= win[1] {
			acc += x.v
			n++
		}
	}
	if n == 0 {
		return 0, false
	}
	return acc / float64(n), true
}

func medianOf(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// roleProcs returns the fdb_process.csv series of every process holding `role`. A process that
// holds several roles appears under each of them (its CPU is the whole process's).
func (d *data) roleProcs(role string) []map[string][]sample {
	var keys []procKey
	for k := range d.fdbProc {
		for _, r := range strings.Split(k.role, ",") {
			if r == role {
				keys = append(keys, k)
				break
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].addr < keys[j].addr })
	out := make([]map[string][]sample, 0, len(keys))
	for _, k := range keys {
		out = append(out, d.fdbProc[k])
	}
	return out
}

// printFDBRoleWindows prints per-role CPU and disk busy statistics (--detailed). For each role,
// every process's mean over each window is one value; the rows summarise that pool of
// processes x windows values. Storage also gets hottest/median rows: in each window the busiest
// process over the median process, summarised across windows.
func (d *data) printFDBRoleWindows(w io.Writer, o Options, from, to int64) {
	if len(d.fdbProc) == 0 || d.intervalMs <= 0 {
		return
	}
	wins := d.cpuWindows(from, to, d.widen(o))
	if len(wins) == 0 {
		return
	}
	winLen := time.Duration(d.intervalMs) * time.Millisecond * time.Duration(d.widen(o))
	var first []sample
	for _, cols := range d.fdbProc {
		if s := cols["cpu_cores"]; len(s) > 0 {
			first = s
			break
		}
	}
	if warn := windowedStatsWarning("FDB process", "fdb_sample_interval_ms", first, from, to, winLen); warn != "" {
		subHeading(w, "FDB per-role statistics", "not shown")
		fmt.Fprintf(w, " [WARN] %s\n", warn)
		return
	}

	type row struct {
		label string
		vals  []float64
		unit  func(float64) string
	}
	f2 := func(v float64) string { return fmt.Sprintf("%.2f", v) }
	f1 := func(v float64) string { return fmt.Sprintf("%.1f", v) }
	ratio := func(v float64) string { return fmt.Sprintf("%.2f", v) }
	var rows []row
	for _, role := range perRoleStatRoles {
		procs := d.roleProcs(role.name)
		if len(procs) == 0 {
			continue
		}
		tag := fmt.Sprintf("%-13s%-6s", role.name, fmt.Sprintf("(%d)", len(procs)))
		type metric struct {
			col, label, short string
			scale             float64
			unit              func(float64) string
		}
		metrics := []metric{{"cpu_cores", "cpu (cores)", "cpu", 1, f2}}
		if role.disk {
			metrics = append(metrics, metric{"disk_busy", "disk busy (%)", "disk busy", 100, f1})
		}
		for _, m := range metrics {
			var pool []float64
			perWin := make([][]float64, len(wins)) // process means per window, for the ratio rows
			for _, p := range procs {
				for i, win := range wins {
					if v, ok := windowMean(p[m.col], win); ok {
						pool = append(pool, v*m.scale)
						perWin[i] = append(perWin[i], v*m.scale)
					}
				}
			}
			rows = append(rows, row{fmt.Sprintf("%s%s", tag, m.label), pool, m.unit})
			if role.name == "storage" {
				var ratios []float64
				for _, vs := range perWin {
					if len(vs) < 2 {
						continue
					}
					sort.Float64s(vs)
					if med := medianOf(vs); med > 0 {
						ratios = append(ratios, vs[len(vs)-1]/med)
					}
				}
				rows = append(rows, row{fmt.Sprintf("%s%s hottest/median", tag, m.short), ratios, ratio})
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	subHeading(w, "FDB per-role statistics", fmt.Sprintf("%d windows of %s", len(wins), winLen),
		"cpu and disk rows pool each process's mean in each window (n = processes x windows)",
		"hottest/median: in each window the busiest process over the median one (n = windows)",
		"min/max/avg/median/pXX are taken across the pool; a process holding several roles counts under each")
	const lw = 46
	fmt.Fprintf(w, " %-*s%7s%9s%9s%9s%9s%9s%9s%9s\n", lw, "", "n", "min", "max", "avg", "median", "p90", "p95", "p99")
	for _, r := range rows {
		if len(r.vals) == 0 {
			continue
		}
		s := stats.Summarize(r.vals, o.Deviation)
		fmt.Fprintf(w, " %-*s%7d%9s%9s%9s%9s%9s%9s%9s\n", lw, r.label, s.N, r.unit(s.Min), r.unit(s.Max),
			r.unit(s.Avg), r.unit(s.Median), r.unit(s.P90), r.unit(s.P95), r.unit(s.P99))
	}
}
