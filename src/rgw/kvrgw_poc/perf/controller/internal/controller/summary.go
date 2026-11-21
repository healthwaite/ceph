package controller

import (
	"fmt"
	"time"

	"kvrgw-perf/internal/results"
	"kvrgw-perf/internal/stats"
)

func (v *invocation) buildSummary(exit int) *results.Summary {
	s := &results.Summary{
		Command: v.o.Command, BenchmarkID: v.benchID, Parameters: v.o.Cfg,
		RunStartUnixS: v.startS, Totals: map[string]results.OpTotals{},
		ServerTotals: v.lastServer, ErrorDescriptions: v.errDescs, Verify: v.verifySum, ExitStatus: exit,
		Failed: exit != 0, Failures: v.failures,
	}
	secs := float64(v.benchEndMs-v.runStartMs) / 1000
	for _, op := range metricOrder {
		m := v.totals[op]
		if m == nil {
			continue
		}
		t := results.OpTotals{Count: m.Count, Errors: m.Errors, ErrorCodes: m.ErrorCodes,
			QueueFull: m.QueueFull, Missed: m.Missed}
		if secs > 0 {
			t.OpsPerSec = float64(m.Count) / secs
		}
		if !stats.IsCounter(op) {
			if m.Count > 0 {
				t.MeanUs = float64(m.SumMicros) / float64(m.Count)
			}
			t.P50Us, t.P90Us = m.Hist.Quantile(0.5), m.Hist.Quantile(0.9)
			t.P99Us, t.P999Us, t.MaxUs = m.Hist.Quantile(0.99), m.Hist.Quantile(0.999), m.Hist.Max()
			s.OpErrors += m.Errors
		}
		s.Totals[op] = t
	}
	if cfg := v.o.Cfg; cfg.OpenLoop() {
		s.TargetOpsPerSec = cfg.RateOpsPerSec * float64(cfg.WorkerCount)
		if op := openLoopMetric(v.o.Command); op != "" {
			s.AchievedOpsPerSec = s.Totals[op].OpsPerSec
		}
	}
	if v.o.Command == "run-put-object-overwrite-versioned" {
		s.VersionsWritten = s.Totals["put_object"].Count
		if n := v.o.Cfg.NumObjectsToOverwrite; n > 0 {
			s.VersionsPerObject = float64(s.VersionsWritten) / float64(n)
		}
	}
	for i, ws := range v.workerSums {
		w := results.WorkerSummary{WorkerIndex: i}
		if ws != nil {
			w.ThreadCounts = ws.ThreadCounts
		}
		s.Workers = append(s.Workers, w)
	}
	return s
}

func (v *invocation) printFinal(s *results.Summary) {
	fmt.Fprintf(v.out, "\n=== %s summary ===\n", s.Command)
	for _, op := range metricOrder {
		t, ok := s.Totals[op]
		if !ok {
			continue
		}
		if stats.IsCounter(op) {
			fmt.Fprintf(v.out, "  %-13s total=%s  %s/s\n", op, human(float64(t.Count)), human(t.OpsPerSec))
			continue
		}
		if stats.IsLag(op) {
			fmt.Fprintf(v.out, "  %-13s (open loop: send time - scheduled time) p50=%s p90=%s p99=%s p999=%s max=%s\n",
				op, fmtUs(t.P50Us), fmtUs(t.P90Us), fmtUs(t.P99Us), fmtUs(t.P999Us), fmtUs(t.MaxUs))
			continue
		}
		extra := ""
		if t.QueueFull > 0 {
			extra += fmt.Sprintf("  queue_full=%d", t.QueueFull)
		}
		if t.Missed > 0 {
			extra += fmt.Sprintf("  missed=%d", t.Missed)
		}
		fmt.Fprintf(v.out, "  %-13s ops=%s  %s ops/s  mean=%s p50=%s p90=%s p99=%s p999=%s max=%s  errors=%d%s\n",
			op, human(float64(t.Count)), human(t.OpsPerSec), fmtUs(uint64(t.MeanUs)), fmtUs(t.P50Us),
			fmtUs(t.P90Us), fmtUs(t.P99Us), fmtUs(t.P999Us), fmtUs(t.MaxUs), t.Errors, extra)
		for _, code := range sortedKeys(t.ErrorCodes) {
			line := fmt.Sprintf("      %-30s x%d", stats.ShortCode(code), t.ErrorCodes[code])
			if d := s.ErrorDescriptions[code]; d != "" {
				line += "  " + d
			}
			fmt.Fprintln(v.out, line)
		}
	}
	if gs := stats.GroupUtils(stats.CumulativeThreadUtils(v.lastServer)); len(gs) > 0 {
		fmt.Fprintf(v.out, "  thread busy (CPU/wall, whole run): %s\n", stats.FormatGroupUtils(gs))
	}
	if s.TargetOpsPerSec > 0 {
		fmt.Fprintf(v.out, "  open loop: target %s ops/s, achieved %s ops/s (latency measured from scheduled send time)\n",
			human(s.TargetOpsPerSec), human(s.AchievedOpsPerSec))
	}
	for _, op := range metricOrder {
		if t, ok := s.Totals[op]; ok && t.QueueFull > 0 {
			fmt.Fprintf(v.out, "  WARNING: %s hit the backend in-flight limit %d times (streams_per_worker > max_inflight_ops)\n", op, t.QueueFull)
		}
		if t, ok := s.Totals[op]; ok && t.Missed > 0 {
			fmt.Fprintf(v.out, "  WARNING: %s missed %d scheduled ops: the target rate was not held\n", op, t.Missed)
		}
	}
	if s.Command == "run-put-object-overwrite-versioned" {
		fmt.Fprintf(v.out, "  versions written: %s  (avg %.2f per object over %d objects)\n",
			human(float64(s.VersionsWritten)), s.VersionsPerObject, v.o.Cfg.NumObjectsToOverwrite)
	}
	if v.fdbStart != nil {
		fmt.Fprintf(v.out, "  fdb disk used: start=%s", humanBytes(v.fdbStart.DiskUsedBytes))
		if v.fdbEnd != nil {
			fmt.Fprintf(v.out, "  end=%s  (+%s)", humanBytes(v.fdbEnd.DiskUsedBytes), humanBytes(v.fdbEnd.DiskUsedBytes-v.fdbStart.DiskUsedBytes))
		}
		fmt.Fprintln(v.out)
	}
	if vs := s.Verify; vs != nil {
		st := "PASS"
		if !vs.Pass {
			st = "FAIL"
		}
		fmt.Fprintf(v.out, "  verify: %s (%d buckets, %d keys checked, %d missing, %d duplicates, took %s)\n",
			st, len(vs.Buckets), vs.KeysChecked, vs.Missing, vs.Duplicate,
			(time.Duration(vs.DurationMs) * time.Millisecond).Round(time.Millisecond))
		for _, smp := range vs.Samples {
			fmt.Fprintf(v.out, "    - %s\n", smp)
		}
		for _, b := range vs.Buckets {
			if b.Missing > 0 {
				fmt.Fprintf(v.out, "    bucket %s: %d missing (first: %v)\n", b.Bucket, b.Missing, b.MissingKeys[:min(len(b.MissingKeys), 3)])
			}
		}
		for _, e := range vs.Errors {
			fmt.Fprintf(v.out, "    ! %s\n", e)
		}
	}
	if s.Failed {
		fmt.Fprintf(v.out, "  RESULT: FAILED (%d reasons; see controller.log)\n", len(s.Failures))
	} else {
		fmt.Fprintf(v.out, "  RESULT: OK\n")
	}
}

// openLoopMetric is the latency metric an open-loop command schedules.
func openLoopMetric(command string) string {
	switch command {
	case "run-put-object", "run-put-object-overwrite", "run-put-object-overwrite-versioned":
		return "put_object"
	case "run-delete-multi":
		return "delete_multi"
	}
	return ""
}

func humanBytes(b float64) string {
	neg := ""
	if b < 0 {
		neg, b = "-", -b
	}
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if b < 1000 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%s%.0f%s", neg, b, u)
			}
			return fmt.Sprintf("%s%.2f%s", neg, b, u)
		}
		b /= 1000
	}
	return ""
}
