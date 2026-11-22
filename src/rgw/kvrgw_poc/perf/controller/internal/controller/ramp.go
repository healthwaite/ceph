package controller

import (
	"fmt"
	"strings"
	"sync"

	pb "kvrgw-perf/gen/perf/v1"
	"kvrgw-perf/internal/ramp"
	"kvrgw-perf/internal/results"
	"kvrgw-perf/internal/stats"
)

// rampDriver runs the open-loop ramp (perf/RAMP.md) inside RunBenchmark. Step 0
// starts with the run (its rate comes from the Init config); step i+1's rate is
// sent to the workers one step ahead, effective on step i+1's first window
// boundary, so steps are contiguous. Each completed window is fed to onWindow
// (in order, under the aggregator lock); a step is evaluated when its last
// window arrives, and the run is cancelled at the first step that does not pass.
type rampDriver struct {
	v        *invocation
	plan     ramp.Plan
	criteria ramp.Criteria
	csv      *results.CSV
	// setRate sends step i's cluster rate to every worker, effective at the
	// given window boundary (ms since the epoch). cancel stops the run.
	setRate func(step int, clusterRate float64, effectiveMs int64)
	cancel  func()

	mu         sync.Mutex
	cur        int // step being collected
	wins       []*stats.Window
	warmEnd    *stats.Window // last window before cur's measurement (nil at run start)
	steps      []results.RampStep
	stopped    bool
	stopReason string
}

func newRampDriver(v *invocation, csv *results.CSV, setRate func(int, float64, int64), cancel func()) (*rampDriver, error) {
	p, err := ramp.NewPlan(&v.o.Cfg)
	if err != nil {
		return nil, err
	}
	return &rampDriver{v: v, plan: p, criteria: ramp.CriteriaFrom(&v.o.Cfg), csv: csv, setRate: setRate, cancel: cancel}, nil
}

func (r *rampDriver) boundaryMs(window int64) int64 { return r.v.runStartMs + window*r.v.intervalMs }

// start announces the plan and sends step 1's rate.
func (r *rampDriver) start() {
	c := r.v.o.Cfg
	fmt.Fprintf(r.v.out, "ramp: %s ops/s, +%s per step, %s warm-up + %s measured per step (%d + %d windows); "+
		"pass if p99 < %g ms, achieved >= %g%%, missed <= %g%%, errors <= %g%%, backlog growth <= %g%%; arrival %s\n",
		human(c.RampStartRate), human(c.RampStep()), c.RampWarmup, c.RampMeasure, r.plan.Warm, r.plan.Measure,
		c.RampMaxP99Ms, c.RampMinAchievedPct, c.RampMaxMissedPct, c.RampMaxErrorPct, c.RampMaxBacklogGrowthPct, c.Arrival)
	if r.plan.Exists(1) {
		r.setRate(1, r.plan.Rate(1), r.boundaryMs(r.plan.StartWindow(1)))
	}
}

func (r *rampDriver) onWindow(w *stats.Window) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	i := r.cur
	switch {
	case w.Index == r.plan.LastWarmWindow(i):
		r.warmEnd = w
	case w.Index > r.plan.LastWarmWindow(i) && w.Index <= r.plan.LastWindow(i):
		r.wins = append(r.wins, w)
	}
	if w.Index != r.plan.LastWindow(i) {
		return
	}
	s := r.evaluate(i)
	r.steps = append(r.steps, s)
	if r.csv != nil {
		r.csv.Row(s.Row()...)
	}
	r.printStep(s)
	switch {
	case s.Verdict == "generator-limited":
		r.stop(fmt.Sprintf("step %d at %s ops/s is generator-limited (result invalid)", i, human(s.TargetOpsPerSec)))
		return
	case s.Verdict != "pass":
		r.stop(fmt.Sprintf("step %d at %s ops/s failed: %s", i, human(s.TargetOpsPerSec), strings.Join(s.Failed, "; ")))
		return
	case !r.plan.Exists(i + 1):
		r.stop(fmt.Sprintf("ramp_max_rate %s ops/s reached", human(r.plan.MaxRate)))
		return
	}
	// Step i+1 is already running; announce i+2.
	r.cur, r.wins, r.warmEnd = i+1, nil, nil
	if r.plan.Warm == 0 {
		r.warmEnd = w // the next step's measurement starts right after this window
	}
	if r.plan.Exists(i + 2) {
		r.setRate(i+2, r.plan.Rate(i+2), r.boundaryMs(r.plan.StartWindow(i+2)))
	}
}

func (r *rampDriver) stop(reason string) {
	r.stopped, r.stopReason = true, reason
	fmt.Fprintf(r.v.out, "ramp: stopping: %s\n", reason)
	r.cancel()
}

// evaluate merges step i's measured windows and applies the criteria.
func (r *rampDriver) evaluate(i int) results.RampStep {
	in := ramp.Input{Step: i, Target: r.plan.Rate(i)}
	var dur int64
	for _, w := range r.wins {
		dur += w.DurationNs
		if m := w.Ops["put_object"]; m != nil {
			in.Op.Merge(m)
		}
		if m := w.Ops["send_lag"]; m != nil {
			in.SendLag.Merge(m)
		}
		if m := w.Ops["service_time"]; m != nil {
			in.Service.Merge(m)
		}
	}
	in.MeasureSecs = float64(dur) / 1e9
	if r.warmEnd != nil {
		in.OutstandingStart = r.warmEnd.Outstanding
	}
	if n := len(r.wins); n > 0 {
		last := r.wins[n-1]
		in.OutstandingEnd = last.Outstanding
		var base map[string]uint64
		if r.warmEnd != nil {
			base = r.warmEnd.Server
		}
		in.DriverBusyMax = driverBusyMax(base, last.Server)
	}
	return ramp.Evaluate(in, r.criteria)
}

// driverBusyMax is the busiest driver thread's CPU/wall between two cumulative
// server-stat snapshots (base nil = since the thread started).
func driverBusyMax(base, last map[string]uint64) float64 {
	var mx float64
	for k, cpu := range last {
		g, w, n, f, ok := stats.ParseThreadKey(k)
		if !ok || g != "driver" || f != "cpu_ns" {
			continue
		}
		wallKey := "thread." + g + "." + w + "." + n + ".wall_ns"
		dc, dw := float64(cpu), float64(last[wallKey])
		if base != nil {
			dc -= float64(base[k])
			dw -= float64(base[wallKey])
		}
		if dw > 0 && dc/dw > mx {
			mx = dc / dw
		}
	}
	return mx
}

func (r *rampDriver) printStep(s results.RampStep) {
	line := fmt.Sprintf("ramp step %d: target %s ops/s, achieved %s (%.1f%%), p99 %.3g ms, missed %.3g%%, errors %.3g%%, "+
		"backlog %+.0f%%, driver busy %.0f%% -> %s", s.Step, human(s.TargetOpsPerSec), human(s.AchievedOpsPerSec),
		s.AchievedPct, s.P99Ms, s.MissedPct, s.ErrorPct, s.BacklogGrowthPct, s.DriverBusyMaxPct, strings.ToUpper(s.Verdict))
	if len(s.Failed) > 0 {
		line += " (" + strings.Join(s.Failed, "; ") + ")"
	}
	fmt.Fprintln(r.v.out, line)
	for _, n := range s.Notes {
		fmt.Fprintf(r.v.out, "  note: %s\n", n)
	}
}

// summary returns the ramp result; reason is used when the ramp did not stop itself.
func (r *rampDriver) summary(otherReason string) *results.RampSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	reason := r.stopReason
	if !r.stopped {
		reason = otherReason
	}
	return ramp.Summarize(r.steps, reason)
}

// setRateMsg builds the per-worker control message.
func setRateMsg(step int, perWorker float64, effectiveMs int64) *pb.RunControl {
	return &pb.RunControl{Msg: &pb.RunControl_SetRate{SetRate: &pb.SetRate{
		Step: int64(step), RateOpsPerSec: perWorker, EffectiveAtUnixNs: effectiveMs * 1_000_000}}}
}
