// Package ramp evaluates open-loop ramp steps (perf/RAMP.md) and plans the step
// sequence. It is pure: the controller feeds it merged window statistics.
package ramp

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"kvrgw-perf/internal/config"
	"kvrgw-perf/internal/results"
	"kvrgw-perf/internal/stats"
)

// GeneratorBusyLimit: a driver this busy makes the step's result invalid.
const GeneratorBusyLimit = 0.85

// Criteria are the per-step sustainability limits.
type Criteria struct {
	MaxP99Ms            float64
	MaxMissedPct        float64
	MaxErrorPct         float64
	MinAchievedPct      float64
	MaxBacklogGrowthPct float64
	// OutstandingCap is the most ops the cluster may have in flight (max_inflight_ops x
	// workers); 0 = unknown.
	OutstandingCap uint64
}

// CriteriaFrom takes the limits from the config.
func CriteriaFrom(c *config.Config) Criteria {
	return Criteria{MaxP99Ms: c.RampMaxP99Ms, MaxMissedPct: c.RampMaxMissedPct, MaxErrorPct: c.RampMaxErrorPct,
		MinAchievedPct: c.RampMinAchievedPct, MaxBacklogGrowthPct: c.RampMaxBacklogGrowthPct,
		OutstandingCap: uint64(c.Kvrgw.MaxInflightOps) * uint64(c.WorkerCount)}
}

// Input is one step's measure window: metrics merged over its windows and workers.
type Input struct {
	Step             int
	Target           float64 // ops/s, cluster total
	MeasureSecs      float64
	Op               stats.Metric // the put metric: count, errors, missed, end-to-end latency
	SendLag          stats.Metric
	Service          stats.Metric
	OutstandingStart uint64 // at the end of the warm-up
	OutstandingEnd   uint64 // at the end of the measure window
	DriverBusyMax    float64
}

func ms(us uint64) float64 { return float64(us) / 1000 }

// Evaluate computes the step's measurements and verdict.
func Evaluate(in Input, cr Criteria) results.RampStep {
	s := results.RampStep{Step: in.Step, TargetOpsPerSec: in.Target, MeasureSecs: in.MeasureSecs,
		Completed: in.Op.Count, Errors: in.Op.Errors, Missed: in.Op.Missed,
		OutstandingStart: in.OutstandingStart, OutstandingEnd: in.OutstandingEnd,
		DriverBusyMaxPct: 100 * in.DriverBusyMax}
	s.Scheduled = in.SendLag.Count + in.Op.Missed
	if in.MeasureSecs > 0 {
		s.AchievedOpsPerSec = float64(in.Op.Count) / in.MeasureSecs
	}
	if in.Target > 0 {
		s.AchievedPct = 100 * s.AchievedOpsPerSec / in.Target
	}
	if s.Scheduled > 0 {
		s.MissedPct = 100 * float64(s.Missed) / float64(s.Scheduled)
	}
	if n := in.Op.Count + in.Op.Errors; n > 0 {
		s.ErrorPct = 100 * float64(in.Op.Errors) / float64(n)
	}
	p99 := in.Op.Hist.Quantile(0.99)
	s.P50Ms, s.P99Ms, s.P999Ms = ms(in.Op.Hist.Quantile(0.5)), ms(p99), ms(in.Op.Hist.Quantile(0.999))
	s.ServiceP99Ms = ms(in.Service.Hist.Quantile(0.99))
	lagP99 := in.SendLag.Hist.Quantile(0.99)
	s.SendLagP99Ms = ms(lagP99)

	// Backlog: in steady state the ops in flight are about rate x mean latency
	// (Little's law), so growth is measured against the larger of that and the
	// count at the start of the window.
	var meanS float64
	if in.Op.Count > 0 {
		meanS = float64(in.Op.SumMicros) / float64(in.Op.Count) / 1e6
	}
	base := float64(in.OutstandingStart)
	if exp := in.Target * meanS; exp > base {
		base = exp
	}
	if base >= 1 {
		s.BacklogGrowthPct = 100 * (float64(in.OutstandingEnd) - base) / base
	}

	if s.AchievedPct < cr.MinAchievedPct {
		s.Failed = append(s.Failed, fmt.Sprintf("achieved %.1f%% < %.4g%%", s.AchievedPct, cr.MinAchievedPct))
	}
	if s.P99Ms >= cr.MaxP99Ms {
		s.Failed = append(s.Failed, fmt.Sprintf("p99 %.3g ms >= %.4g ms", s.P99Ms, cr.MaxP99Ms))
	}
	if s.MissedPct > cr.MaxMissedPct {
		s.Failed = append(s.Failed, fmt.Sprintf("missed %.3g%% > %.4g%%", s.MissedPct, cr.MaxMissedPct))
	}
	if s.ErrorPct > cr.MaxErrorPct {
		s.Failed = append(s.Failed, fmt.Sprintf("errors %.3g%% > %.4g%%", s.ErrorPct, cr.MaxErrorPct))
	}
	if s.BacklogGrowthPct > cr.MaxBacklogGrowthPct {
		s.Failed = append(s.Failed, fmt.Sprintf("backlog +%.0f%% > %.4g%%", s.BacklogGrowthPct, cr.MaxBacklogGrowthPct))
	}

	// Is the load generator itself the limit?
	var limited []string
	if in.DriverBusyMax >= GeneratorBusyLimit {
		limited = append(limited, fmt.Sprintf("driver %.0f%% busy", 100*in.DriverBusyMax))
	}
	if stats.SendLagSignificant(lagP99, p99) {
		limited = append(limited, fmt.Sprintf("send lag p99 %.3g ms", s.SendLagP99Ms))
	}
	// Little's-law check: misses near the outstanding cap come from the cap.
	if cr.OutstandingCap > 0 {
		if exp := in.Target * float64(p99) / 1e6; exp >= 0.5*float64(cr.OutstandingCap) {
			s.Notes = append(s.Notes, fmt.Sprintf(
				"expected in-flight ops (rate x p99 = %.0f) are near the outstanding cap (%d = max_inflight_ops x workers): "+
					"misses may come from the cap; raise max_inflight_ops", exp, cr.OutstandingCap))
		}
	}
	switch {
	case len(limited) > 0:
		s.Verdict = "generator-limited"
		s.Notes = append(s.Notes, "load generator is the limit ("+joinComma(limited)+
			"): result invalid; raise driver_threads or worker_count")
	case len(s.Failed) > 0:
		s.Verdict = "fail"
	default:
		s.Verdict = "pass"
	}
	return s
}

func joinComma(a []string) string {
	out := ""
	for i, x := range a {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// Summarize builds the summary from the evaluated steps.
func Summarize(steps []results.RampStep, stopReason string) *results.RampSummary {
	r := &results.RampSummary{Steps: steps, StopReason: stopReason}
	for _, s := range steps {
		if s.Verdict == "pass" && s.TargetOpsPerSec > r.MaxSustainableOpsPerSec {
			r.MaxSustainableOpsPerSec = s.TargetOpsPerSec
		}
		if s.AchievedOpsPerSec > r.MaxAchievedOpsPerSec {
			r.MaxAchievedOpsPerSec = s.AchievedOpsPerSec
		}
	}
	return r
}

// Plan maps steps onto report windows: step i covers windows [i*Len, (i+1)*Len), the
// first Warm of them warm-up and the rest measured.
type Plan struct {
	Warm, Measure int64 // windows
	MaxRate       float64
	Cfg           *config.Config
}

// NewPlan rounds ramp_warmup / ramp_measure up to whole windows.
func NewPlan(c *config.Config) (Plan, error) {
	w, m, err := c.RampDurations()
	if err != nil {
		return Plan{}, err
	}
	iv := c.ReportIntervalMs
	up := func(ms int64) int64 { return (ms + iv - 1) / iv }
	return Plan{Warm: up(w.Milliseconds()), Measure: up(m.Milliseconds()), MaxRate: c.RampMaxRate, Cfg: c}, nil
}

// Len is the windows per step.
func (p Plan) Len() int64 { return p.Warm + p.Measure }

// Rate is step i's target (cluster total).
func (p Plan) Rate(i int) float64 { return p.Cfg.RampRate(i) }

// Exists reports whether step i is within ramp_max_rate.
func (p Plan) Exists(i int) bool { return p.MaxRate <= 0 || p.Rate(i) <= p.MaxRate*(1+1e-9) }

// StartWindow is the first window of step i.
func (p Plan) StartWindow(i int) int64 { return int64(i) * p.Len() }

// LastWarmWindow is the window whose end is the start of step i's measurement (-1 at the run start).
func (p Plan) LastWarmWindow(i int) int64 { return p.StartWindow(i) + p.Warm - 1 }

// LastWindow is step i's last window.
func (p Plan) LastWindow(i int) int64 { return p.StartWindow(i+1) - 1 }

// num renders a rate with thousands separators.
func num(f float64) string {
	s := strconv.FormatInt(int64(f+0.5), 10)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// PrintTable prints the ramp steps and results (run summary and report).
func PrintTable(w io.Writer, r *results.RampSummary) {
	fmt.Fprintf(w, "\n  ramp: %d step(s) evaluated; stopped: %s\n", len(r.Steps), r.StopReason)
	if len(r.Steps) > 0 {
		fmt.Fprintf(w, "  %4s %11s %11s %8s %9s %9s %9s %8s %7s %8s %7s  %s\n", "step", "target/s", "achieved/s", "achv%",
			"p50_ms", "p99_ms", "svc_p99", "missed%", "err%", "backlog", "drv%", "verdict")
		for _, s := range r.Steps {
			fmt.Fprintf(w, "  %4d %11s %11s %7.1f%% %9.3g %9.3g %9.3g %7.3g%% %6.3g%% %+7.0f%% %6.0f%%  %s",
				s.Step, num(s.TargetOpsPerSec), num(s.AchievedOpsPerSec), s.AchievedPct, s.P50Ms, s.P99Ms,
				s.ServiceP99Ms, s.MissedPct, s.ErrorPct, s.BacklogGrowthPct, s.DriverBusyMaxPct, s.Verdict)
			if len(s.Failed) > 0 {
				fmt.Fprintf(w, " (%s)", strings.Join(s.Failed, "; "))
			}
			fmt.Fprintln(w)
		}
	}
	if r.MaxSustainableOpsPerSec > 0 {
		fmt.Fprintf(w, "  max sustainable: %s ops/s (highest target that passed every criterion)\n", num(r.MaxSustainableOpsPerSec))
	} else {
		fmt.Fprintln(w, "  max sustainable: none (no step passed; lower ramp_start_rate)")
	}
	fmt.Fprintf(w, "  max achieved:    %s ops/s (highest completed rate of any step)\n", num(r.MaxAchievedOpsPerSec))
}
