package report

import (
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"kvrgw-perf/internal/stats"
)

// storageCPUImbalance is the max/median ratio of per-process storage CPU above which the
// health section warns about a hot storage process (a hot shard or range).
const storageCPUImbalance = 1.8

// cpuProc is one FDB process's CPU samples (fdb_cpu.csv) and the roles it holds.
type cpuProc struct {
	roles   []string
	samples []sample
}

type roleCPU struct {
	role  string
	cores float64
	procs int
}

type procCPU struct {
	addr  string
	cores float64
}

// fdbCPUSummary is the CPU of the cluster over the analysed range: each process's mean CPU,
// summed per role label. A process holding several roles counts under each of them but only
// once in the total.
type fdbCPUSummary struct {
	roles      []roleCPU // by cores, descending
	totalCores float64
	totalProcs int
	storage    []procCPU // storage processes, by cores descending
}

type storageSpread struct {
	min, median, mean, max, stddev float64
}

func (d *data) fdbCPUSummary(from, to int64) fdbCPUSummary {
	var sum fdbCPUSummary
	byRole := map[string]*roleCPU{}
	addrs := make([]string, 0, len(d.fdbCPU))
	for a := range d.fdbCPU {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		p := d.fdbCPU[addr]
		v := inSamples(p.samples, from, to)
		if len(v) == 0 {
			continue
		}
		var mean float64
		for _, x := range v {
			mean += x
		}
		mean /= float64(len(v))
		sum.totalCores += mean
		sum.totalProcs++
		for _, r := range p.roles {
			rc := byRole[r]
			if rc == nil {
				rc = &roleCPU{role: r}
				byRole[r] = rc
			}
			rc.cores += mean
			rc.procs++
			if r == "storage" {
				sum.storage = append(sum.storage, procCPU{addr, mean})
			}
		}
	}
	for _, rc := range byRole {
		sum.roles = append(sum.roles, *rc)
	}
	sort.Slice(sum.roles, func(i, j int) bool {
		if sum.roles[i].cores != sum.roles[j].cores {
			return sum.roles[i].cores > sum.roles[j].cores
		}
		return sum.roles[i].role < sum.roles[j].role
	})
	sort.Slice(sum.storage, func(i, j int) bool {
		if sum.storage[i].cores != sum.storage[j].cores {
			return sum.storage[i].cores > sum.storage[j].cores
		}
		return sum.storage[i].addr < sum.storage[j].addr
	})
	return sum
}

// spread describes how evenly storage CPU is spread over the storage processes (population
// standard deviation, as fdb_cpu_usage.sh does).
func (s fdbCPUSummary) spread() (storageSpread, bool) {
	n := len(s.storage)
	if n == 0 {
		return storageSpread{}, false
	}
	v := make([]float64, n)
	for i, p := range s.storage {
		v[i] = p.cores
	}
	sort.Float64s(v)
	var sp storageSpread
	sp.min, sp.max = v[0], v[n-1]
	if n%2 == 1 {
		sp.median = v[n/2]
	} else {
		sp.median = (v[n/2-1] + v[n/2]) / 2
	}
	for _, x := range v {
		sp.mean += x
	}
	sp.mean /= float64(n)
	for _, x := range v {
		sp.stddev += (x - sp.mean) * (x - sp.mean)
	}
	sp.stddev = math.Sqrt(sp.stddev / float64(n))
	return sp, true
}

// imbalance is max/median of storage CPU; ok is false with fewer than two storage processes or
// a zero median, where the ratio means nothing.
func (s fdbCPUSummary) imbalance() (ratio float64, ok bool) {
	sp, has := s.spread()
	if !has || len(s.storage) < 2 || sp.median <= 0 {
		return 0, false
	}
	return sp.max / sp.median, true
}

// printFDBCPU prints the "CPU by role" table (nothing for results without fdb_cpu.csv).
func (d *data) printFDBCPU(w io.Writer, from, to int64) {
	if len(d.fdbCPU) == 0 {
		return
	}
	sum := d.fdbCPUSummary(from, to)
	if sum.totalProcs == 0 {
		return
	}
	addrs := make([]string, 0, len(d.fdbCPU))
	for a := range d.fdbCPU {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	subHeading(w, "CPU by role", fmt.Sprintf("%s analysed, %s", time.Duration(to-from)*time.Millisecond,
		sampleNote(d.fdbCPU[addrs[0]].samples, from, to)),
		"mean cores per process over the run; a process holding several roles counts under each role and once in the total")
	width := 4
	for _, r := range sum.roles {
		if len(r.role) > width {
			width = len(r.role)
		}
	}
	width += 2
	fmt.Fprintf(w, " %-*s%8s%7s%10s\n", width, "role", "cores", "procs", "avg/proc")
	for _, r := range sum.roles {
		fmt.Fprintf(w, " %-*s%8.2f%7d%10.3f\n", width, r.role, r.cores, r.procs, r.cores/float64(r.procs))
	}
	tail := ""
	if hz := inSamples(d.fdbCluster["txn_hz"], from, to); len(hz) > 0 {
		var avg float64
		for _, x := range hz {
			avg += x
		}
		if avg /= float64(len(hz)); avg > 0 {
			tail = fmt.Sprintf("   %.2f cores per 1,000 committed txn/s", sum.totalCores/(avg/1000))
		}
	}
	fmt.Fprintf(w, " %-*s%8.2f%7d%10.3f%s\n", width, "total", sum.totalCores, sum.totalProcs,
		sum.totalCores/float64(sum.totalProcs), tail)
	if sp, ok := sum.spread(); ok {
		fmt.Fprintf(w, "\n Storage CPU spread (cores/process): min=%.3f median=%.3f mean=%.3f max=%.3f stddev=%.3f\n",
			sp.min, sp.median, sp.mean, sp.max, sp.stddev)
		if r, ok := sum.imbalance(); ok {
			fmt.Fprintf(w, "   max/median %.1fx", r)
			top := sum.storage
			if len(top) > 3 {
				top = top[:3]
			}
			fmt.Fprint(w, "   hottest:")
			for i, p := range top {
				sep := ","
				if i == 0 {
					sep = ""
				}
				fmt.Fprintf(w, "%s %s %.2f", sep, p.addr, p.cores)
			}
			fmt.Fprintln(w)
		}
	}
}

// storageImbalanceWarning returns the health warning for a hot storage process, or "".
func (d *data) storageImbalanceWarning(from, to int64) string {
	if len(d.fdbCPU) == 0 {
		return ""
	}
	sum := d.fdbCPUSummary(from, to)
	r, ok := sum.imbalance()
	if !ok || r <= storageCPUImbalance {
		return ""
	}
	sp, _ := sum.spread()
	return fmt.Sprintf("storage CPU imbalance: hottest %s at %.2f cores is %.1fx the median (%.2f); a hot shard or range?",
		sum.storage[0].addr, sum.storage[0].cores, r, sp.median)
}

// procWindowMeans returns each process's mean CPU over the samples in (start,end], skipping
// processes with no sample there.
func (d *data) procWindowMeans(win [2]int64) map[string]float64 {
	out := map[string]float64{}
	for addr, p := range d.fdbCPU {
		var acc float64
		var n int
		for _, x := range p.samples {
			if x.ts > win[0] && x.ts <= win[1] {
				acc += x.v
				n++
			}
		}
		if n > 0 {
			out[addr] = acc / float64(n)
		}
	}
	return out
}

func (p *cpuProc) hasRole(role string) bool {
	for _, r := range p.roles {
		if r == role {
			return true
		}
	}
	return false
}

// printFDBCPUWindows prints per-window statistics of FDB CPU (--detailed): total, storage and
// log cores, and how unevenly storage CPU is spread. Like the other sampled tables it needs the
// FDB sample interval to fit the window, otherwise a warning explains why it is not shown.
func (d *data) printFDBCPUWindows(w io.Writer, o Options, from, to int64) {
	if len(d.fdbCPU) == 0 || d.intervalMs <= 0 {
		return
	}
	wins := d.cpuWindows(from, to, d.widen(o))
	if len(wins) == 0 {
		return
	}
	winLen := time.Duration(d.intervalMs) * time.Millisecond * time.Duration(d.widen(o))
	addrs := make([]string, 0, len(d.fdbCPU))
	var all [][]sample
	for a := range d.fdbCPU {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		all = append(all, d.fdbCPU[a].samples)
	}
	if warn := windowedStatsWarning("FDB CPU", "fdb_sample_interval_ms", all[0], from, to, winLen); warn != "" {
		subHeading(w, "CPU per-window statistics", "not shown")
		fmt.Fprintf(w, " [WARN] %s\n", warn)
		return
	}
	var total, storage, logc, ratio, hottest []float64
	withData := 0
	for _, win := range wins {
		means := d.procWindowMeans(win)
		if len(means) == 0 {
			continue
		}
		withData++
		var t, s, l float64
		var sv []float64
		for addr, m := range means {
			t += m
			p := d.fdbCPU[addr]
			if p.hasRole("storage") {
				s += m
				sv = append(sv, m)
			}
			if p.hasRole("log") {
				l += m
			}
		}
		total = append(total, t)
		if len(sv) > 0 {
			storage = append(storage, s)
			sort.Float64s(sv)
			hottest = append(hottest, sv[len(sv)-1])
			if len(sv) >= 2 {
				med := sv[len(sv)/2]
				if len(sv)%2 == 0 {
					med = (sv[len(sv)/2-1] + sv[len(sv)/2]) / 2
				}
				if med > 0 {
					ratio = append(ratio, sv[len(sv)-1]/med)
				}
			}
		}
		if l > 0 {
			logc = append(logc, l)
		}
	}
	subHeading(w, "CPU per-window statistics", windowsNote(withData, len(wins), winLen),
		"each row is the mean of the FDB CPU samples in each window; min/max/avg/median/pXX/dev% are taken across those windows")
	const lw = 24
	fmt.Fprintf(w, " %-*s%9s%9s%9s%9s%9s%9s%9s%8s\n", lw, "", "min", "max", "avg", "median", "p90", "p95", "p99", "dev%")
	f2 := func(v float64) string { return fmt.Sprintf("%.2f", v) }
	rowAt := func(label string, vals []float64) {
		if len(vals) == 0 {
			return
		}
		s := stats.Summarize(vals, o.Deviation)
		fmt.Fprintf(w, " %-*s%9s%9s%9s%9s%9s%9s%9s%7.1f%%\n", lw, label, f2(s.Min), f2(s.Max), f2(s.Avg),
			f2(s.Median), f2(s.P90), f2(s.P95), f2(s.P99), s.DevPct)
	}
	rowAt("total (cores)", total)
	rowAt("storage (cores)", storage)
	rowAt("log (cores)", logc)
	rowAt("storage max/median", ratio)
	rowAt("hottest storage (cores)", hottest)
}
