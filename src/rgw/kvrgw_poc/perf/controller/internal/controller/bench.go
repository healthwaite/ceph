package controller

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "kvrgw-perf/gen/perf/v1"
	"kvrgw-perf/internal/results"
	"kvrgw-perf/internal/stats"
)

// metricOrder gives a stable output order for op types.
var metricOrder = []string{"put_object", "list_objects", "delete_multi", "list_delete_multi", "keys_listed", "keys_deleted"}

func (v *invocation) runBenchmark(sigCtx, mctx context.Context, benchStarted chan struct{}) ([]*pb.RunSummary, bool) {
	cfg := v.o.Cfg
	var err error
	if v.metricsCSV, err = v.dir.OpenCSV("metrics.csv", results.MetricsHeader...); err != nil {
		v.fail("metrics.csv: %v", err)
		return nil, false
	}
	defer v.metricsCSV.Close()
	if v.histCSV, err = v.dir.OpenCSV("hist.csv", results.HistHeader...); err != nil {
		v.fail("hist.csv: %v", err)
		return nil, false
	}
	defer v.histCSV.Close()
	if v.serverCSV, err = v.dir.OpenCSV("server_stats.csv", results.ServerStatsHeader...); err != nil {
		v.fail("server_stats.csv: %v", err)
		return nil, false
	}
	defer v.serverCSV.Close()
	if v.errorsCSV, err = v.dir.OpenCSV("errors.csv", results.ErrorsHeader...); err != nil {
		v.fail("errors.csv: %v", err)
		return nil, false
	}
	defer v.errorsCSV.Close()
	v.errDescs = map[string]string{}
	v.totals = map[string]*stats.Metric{}
	v.cum = map[string][2]uint64{}
	v.seenOps = map[string]bool{}

	n := len(v.workers)
	agg := stats.NewAggregator(n)
	var aggMu sync.Mutex

	runStart := time.Now().Add(time.Second)
	v.runStartMs = runStart.UnixMilli()
	v.intervalMs = cfg.ReportIntervalMs
	v.ev.At(v.runStartMs, "benchmark_start")
	time.AfterFunc(time.Until(runStart), func() { v.setFDBPhase("benchmark") })
	fmt.Fprintf(v.out, "benchmark starting in 1s (%d workers x %d threads)\n", cfg.WorkerCount, cfg.ThreadsPerWorker)

	streams := make([]grpc.BidiStreamingClient[pb.RunControl, pb.PhaseEvent], n)
	sendMu := make([]sync.Mutex, n)
	summaries := make([]*pb.RunSummary, n)
	workerErr := make([]string, n)

	cancelAll := func() {
		for i := range streams {
			sendMu[i].Lock()
			if streams[i] != nil {
				streams[i].Send(&pb.RunControl{Msg: &pb.RunControl_Cancel{Cancel: &pb.Cancel{}}})
			}
			sendMu[i].Unlock()
		}
	}

	// Open streams and send the first message before any events are consumed.
	for i, w := range v.workers {
		st, err := w.client.RunBenchmark(mctx)
		if err != nil {
			v.fail("RunBenchmark on worker %d: %v", i, err)
			return nil, false
		}
		sendMu[i].Lock()
		streams[i] = st
		err = st.Send(&pb.RunControl{BenchmarkId: v.benchID, RunStartUnixNs: runStart.UnixNano(),
			ReportIntervalMs: cfg.ReportIntervalMs})
		sendMu[i].Unlock()
		if err != nil {
			v.fail("RunBenchmark send on worker %d: %v", i, err)
			return nil, false
		}
	}
	close(benchStarted)
	stopSig := make(chan struct{})
	defer close(stopSig)
	go func() {
		select {
		case <-sigCtx.Done():
			fmt.Fprintln(v.out, "\ninterrupt: asking workers to stop...")
			cancelAll()
		case <-stopSig:
		}
	}()

	var wg sync.WaitGroup
	for i := range v.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := streams[i]
			for {
				ev, err := st.Recv()
				if err == io.EOF {
					if summaries[i] == nil && workerErr[i] == "" {
						workerErr[i] = "stream ended without DONE"
					}
					break
				}
				if err != nil {
					workerErr[i] = err.Error()
					break
				}
				if ev.State == pb.PhaseEvent_DONE {
					summaries[i] = ev.RunSummary
					if ev.Error != "" {
						workerErr[i] = ev.Error
					}
					break
				}
				if ev.Progress != nil {
					aggMu.Lock()
					for k, t := range ev.Progress.ErrorDescriptions {
						v.errDescs[k] = t
					}
					wins := agg.Add(i, ev.Progress)
					v.handleWindows(wins)
					aggMu.Unlock()
				}
			}
			sendMu[i].Lock()
			st.CloseSend()
			sendMu[i].Unlock()
			if workerErr[i] != "" {
				v.fail("worker %d: %s", i, workerErr[i])
				cancelAll() // a failed worker fails the invocation: stop the others
			}
			aggMu.Lock()
			v.handleWindows(agg.Finish(i))
			aggMu.Unlock()
		}()
	}
	wg.Wait()
	aggMu.Lock()
	v.handleWindows(agg.Flush())
	aggMu.Unlock()
	v.benchEndMs = time.Now().UnixMilli()
	v.ev.At(v.benchEndMs, "benchmark_end")
	v.setFDBPhase("post")

	ok := true
	for _, e := range workerErr {
		if e != "" {
			ok = false
		}
	}
	return summaries, ok
}

// handleWindows writes completed windows to the CSVs and the terminal.
func (v *invocation) handleWindows(wins []*stats.Window) {
	for _, w := range wins {
		durMs := w.DurationNs / 1e6
		if durMs <= 0 {
			durMs = v.intervalMs
		}
		ts := v.runStartMs + w.Index*v.intervalMs + durMs
		secs := float64(w.DurationNs) / 1e9
		if secs <= 0 {
			secs = float64(v.intervalMs) / 1000
		}
		var parts []string
		for _, op := range metricOrder {
			m := w.Ops[op]
			if m == nil {
				m = &stats.Metric{}
			}
			if !v.seenOps[op] && m.Empty() {
				continue
			}
			v.seenOps[op] = true
			t := v.totals[op]
			if t == nil {
				t = &stats.Metric{}
				v.totals[op] = t
			}
			t.Merge(m)
			c := v.cum[op]
			c[0] += m.Count
			c[1] += m.Errors
			v.cum[op] = c
			rate := float64(m.Count) / secs
			errNote := ""
			if m.Errors > 0 && !stats.IsCounter(op) {
				for _, code := range sortedKeys(m.ErrorCodes) {
					v.errorsCSV.Row(results.I(ts), results.I(w.Index), op, code, results.U(m.ErrorCodes[code]))
				}
				errNote = " [" + stats.FormatErrorCodes(m.ErrorCodes) + "]"
			}
			if stats.IsCounter(op) {
				v.metricsCSV.Row(results.I(ts), results.I(w.Index), op, results.U(m.Count), results.U(m.Errors),
					results.F(rate), "", "", "", "", "", "", results.U(c[0]), results.U(c[1]))
				parts = append(parts, fmt.Sprintf("%s %s/s total=%s", op, human(rate), human(float64(c[0]))))
				continue
			}
			var mean float64
			if m.Count > 0 {
				mean = float64(m.SumMicros) / float64(m.Count)
			}
			v.metricsCSV.Row(results.I(ts), results.I(w.Index), op, results.U(m.Count), results.U(m.Errors),
				results.F(rate), results.F(mean), results.U(m.Hist.Quantile(0.5)), results.U(m.Hist.Quantile(0.9)),
				results.U(m.Hist.Quantile(0.99)), results.U(m.Hist.Quantile(0.999)), results.U(m.Hist.Max()),
				results.U(c[0]), results.U(c[1]))
			idx, cnt := m.Hist.Sparse()
			for k := range idx {
				v.histCSV.Row(results.I(w.Index), op, results.I(int64(idx[k])), results.U(cnt[k]))
			}
			parts = append(parts, fmt.Sprintf("%s %s ops/s total=%s p50=%s p99=%s err=%d%s", op, human(rate),
				human(float64(c[0])), fmtUs(m.Hist.Quantile(0.5)), fmtUs(m.Hist.Quantile(0.99)), m.Errors, errNote))
		}
		for _, name := range sortedKeys(w.Server) {
			v.serverCSV.Row(results.I(ts), results.I(w.Index), name, results.U(w.Server[name]))
		}
		v.lastServer = w.Server
		v.windows++
		fmt.Fprintln(v.out, progressLine(v.o.Command, fmtOffset(w.Index*v.intervalMs), parts))
	}
}

// progressLine formats one progress report. run-list-delete-multi reports five metrics, so each
// goes on its own indented line; the other commands keep one " | "-separated line.
func progressLine(command, offset string, parts []string) string {
	if command == "run-list-delete-multi" {
		return "[t=" + offset + "]\n\t" + strings.Join(parts, "\n\t")
	}
	return "[t=" + offset + "] " + strings.Join(parts, " | ")
}

// fmtOffset renders a millisecond offset from run start as e.g. "0s", "10s", "1.5s".
func fmtOffset(ms int64) string {
	if ms%1000 == 0 {
		return fmt.Sprintf("%ds", ms/1000)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

func human(f float64) string {
	n := int64(f + 0.5)
	s := fmt.Sprintf("%d", n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// fmtUs renders a microsecond latency in milliseconds to 3 significant figures.
func fmtUs(us uint64) string { return stats.Ms(float64(us)) }
