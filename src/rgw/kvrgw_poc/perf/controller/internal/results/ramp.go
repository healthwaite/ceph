package results

import "strconv"

// RampStep is one evaluated ramp step (perf/RAMP.md): what was offered, what
// happened over its measure window, and the verdict.
type RampStep struct {
	Step              int     `json:"step"`
	TargetOpsPerSec   float64 `json:"target_ops_per_sec"` // cluster total
	MeasureSecs       float64 `json:"measure_secs"`
	Scheduled         uint64  `json:"scheduled"` // issued + missed
	Completed         uint64  `json:"completed"`
	Errors            uint64  `json:"errors"`
	Missed            uint64  `json:"missed"`
	AchievedOpsPerSec float64 `json:"achieved_ops_per_sec"`
	AchievedPct       float64 `json:"achieved_pct"`
	MissedPct         float64 `json:"missed_pct"`
	ErrorPct          float64 `json:"error_pct"`
	P50Ms             float64 `json:"p50_ms"` // end to end, from scheduled time
	P99Ms             float64 `json:"p99_ms"`
	P999Ms            float64 `json:"p999_ms"`
	ServiceP99Ms      float64 `json:"service_p99_ms"`  // send -> completion
	SendLagP99Ms      float64 `json:"send_lag_p99_ms"` // send - scheduled
	MeanMs            float64 `json:"mean_ms"`
	// LittleMaxOpsPerSec is the in-flight cap / mean latency: the most the cluster
	// could complete at this step's latency (0 when unknown).
	LittleMaxOpsPerSec float64 `json:"little_max_ops_per_sec"`
	OutstandingStart   uint64  `json:"outstanding_start"`
	OutstandingEnd     uint64  `json:"outstanding_end"`
	BacklogGrowthPct   float64 `json:"backlog_growth_pct"`
	DriverBusyMaxPct   float64 `json:"driver_busy_max_pct"`
	// Verdict is "pass", "fail" or "generator-limited" (result invalid).
	Verdict string   `json:"verdict"`
	Failed  []string `json:"failed,omitempty"` // the criteria that failed
	Notes   []string `json:"notes,omitempty"`
}

// RampSummary is the ramp section of summary.json.
type RampSummary struct {
	Steps []RampStep `json:"steps"`
	// MaxSustainableOpsPerSec is the highest target that passed every criterion;
	// 0 when no step passed.
	MaxSustainableOpsPerSec float64 `json:"max_sustainable_ops_per_sec"`
	// MaxAchievedOpsPerSec is the highest completed rate of any step, sustainable or not.
	MaxAchievedOpsPerSec float64 `json:"max_achieved_ops_per_sec"`
	StopReason           string  `json:"stop_reason"`
	// Mode is ramp_mode ("sla" or "throughput"); MinAchievedPct its achieved threshold.
	Mode           string  `json:"mode"`
	MinAchievedPct float64 `json:"min_achieved_pct"`
}

// RampStepsHeader is the header of ramp_steps.csv.
var RampStepsHeader = []string{"step", "target_ops_per_sec", "measure_secs", "scheduled", "completed",
	"errors", "missed", "achieved_ops_per_sec", "achieved_pct", "missed_pct", "error_pct", "p50_ms",
	"p99_ms", "p999_ms", "service_p99_ms", "send_lag_p99_ms", "outstanding_start", "outstanding_end",
	"backlog_growth_pct", "driver_busy_max_pct", "mean_ms", "little_max_ops_per_sec", "verdict", "failed"}

// Row renders a step as a ramp_steps.csv row.
func (s RampStep) Row() []string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
	failed := ""
	for i, x := range s.Failed {
		if i > 0 {
			failed += "; "
		}
		failed += x
	}
	return []string{I(int64(s.Step)), f(s.TargetOpsPerSec), f(s.MeasureSecs), U(s.Scheduled), U(s.Completed),
		U(s.Errors), U(s.Missed), f(s.AchievedOpsPerSec), f(s.AchievedPct), f(s.MissedPct), f(s.ErrorPct),
		f(s.P50Ms), f(s.P99Ms), f(s.P999Ms), f(s.ServiceP99Ms), f(s.SendLagP99Ms), U(s.OutstandingStart),
		U(s.OutstandingEnd), f(s.BacklogGrowthPct), f(s.DriverBusyMaxPct), f(s.MeanMs), f(s.LittleMaxOpsPerSec),
		s.Verdict, failed}
}
