package controller

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	pb "kvrgw-perf/gen/perf/v1"
	"kvrgw-perf/internal/results"
)

func (v *invocation) buildThreadCounts(sums []*pb.RunSummary) []uint64 {
	if v.o.Command != "run-put-object" && v.o.Command != "run-delete-multi" {
		return nil
	}
	cfg := v.o.Cfg
	counts := make([]uint64, cfg.WorkerCount*cfg.ThreadsPerWorker)
	for w, s := range sums {
		if s == nil {
			continue
		}
		for t, c := range s.ThreadCounts {
			if g := w*cfg.ThreadsPerWorker + t; g < len(counts) {
				counts[g] = c
			}
		}
	}
	return counts
}

func (v *invocation) verify(mctx context.Context, sums []*pb.RunSummary) bool {
	counts := v.buildThreadCounts(sums)
	fmt.Fprintln(v.out, "verifying...")
	v.ev.Now("verify_start")
	v.setFDBPhase("verify")
	t0 := time.Now()
	res := make([]*pb.PhaseEvent, len(v.workers))
	prog := newVerifyProgress(len(v.workers), t0)
	stop := make(chan struct{})
	printed := make(chan struct{})
	if v.o.Cfg.ReportIntervalMs > 0 {
		go func() {
			defer close(printed)
			tk := time.NewTicker(time.Duration(v.o.Cfg.ReportIntervalMs) * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tk.C:
					fmt.Fprintln(v.out, prog.line(time.Now()))
				}
			}
		}()
	} else {
		close(printed)
	}
	errs := v.forAll(func(i int, w *workerConn) error {
		st, err := w.client.Verify(mctx, &pb.VerifyRequest{BenchmarkId: v.benchID, ThreadCounts: counts,
			ReportIntervalMs: v.o.Cfg.ReportIntervalMs})
		if err != nil {
			return err
		}
		return drainTerminal(st, func(ev *pb.PhaseEvent) error {
			res[i] = ev
			return nil
		}, prog.update)
	})
	close(stop)
	<-printed
	v.ev.Now("verify_end")
	v.setFDBPhase("post")
	vs := &results.VerifySummary{Ran: true, DurationMs: time.Since(t0).Milliseconds()}
	v.verifySum = vs
	pass := true
	for i, e := range errs {
		if e != nil {
			vs.Errors = append(vs.Errors, fmt.Sprintf("worker %d: %v", i, e))
			pass = false
		}
	}
	for i, ev := range res {
		if ev == nil {
			continue
		}
		if ev.Error != "" {
			vs.Errors = append(vs.Errors, fmt.Sprintf("worker %d: %s", i, ev.Error))
			pass = false
		}
		r := ev.Verify
		if r == nil {
			continue
		}
		for _, b := range r.Buckets {
			vs.Buckets = append(vs.Buckets, results.BucketVerify{Bucket: b.Bucket, Expected: b.Expected,
				Found: b.Found, Missing: b.Missing, MissingKeys: b.MissingKeys})
			vs.Missing += b.Missing
		}
		vs.KeysChecked += r.KeysChecked
		vs.BadKey += r.BadKey
		vs.OutOfRange += r.OutOfRange
		vs.Unexpected += r.Unexpected
		vs.Duplicate += r.Duplicate
		vs.OtherFailures += r.OtherFailures
		vs.Samples = append(vs.Samples, r.Samples...)
	}
	sort.Slice(vs.Buckets, func(a, b int) bool { return vs.Buckets[a].Bucket < vs.Buckets[b].Bucket })
	if vs.Missing+vs.BadKey+vs.OutOfRange+vs.Unexpected+vs.Duplicate+vs.OtherFailures > 0 {
		pass = false
	}
	vs.Pass = pass
	if !pass {
		v.fail("verify failed: missing=%d bad_key=%d out_of_range=%d unexpected=%d duplicate=%d other=%d",
			vs.Missing, vs.BadKey, vs.OutOfRange, vs.Unexpected, vs.Duplicate, vs.OtherFailures)
	}
	return pass
}

// verifyProgress aggregates the workers' periodic VerifyProgress events into one status line.
type verifyProgress struct {
	mu    sync.Mutex
	t0    time.Time
	cur   []uint64 // keys_checked per worker
	total []uint64 // keys_total per worker (0 = unknown)
}

func newVerifyProgress(workers int, t0 time.Time) *verifyProgress {
	return &verifyProgress{t0: t0, cur: make([]uint64, workers), total: make([]uint64, workers)}
}

func (p *verifyProgress) update(ev *pb.PhaseEvent) {
	vp := ev.VerifyProgress
	if vp == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if i := int(vp.WorkerIndex); i >= 0 && i < len(p.cur) {
		p.cur[i], p.total[i] = vp.KeysChecked, vp.KeysTotal
	}
}

func (p *verifyProgress) line(now time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var done, total uint64
	known := true
	for i := range p.cur {
		done += p.cur[i]
		total += p.total[i]
		if p.total[i] == 0 {
			known = false // some worker's total is unknown, so a percentage would mislead
		}
	}
	el := now.Sub(p.t0)
	rate := 0.0
	if el > 0 {
		rate = float64(done) / el.Seconds()
	}
	s := fmt.Sprintf("[verify %s] %s keys checked", el.Round(time.Second), commas(done))
	if known && total > 0 {
		pct := 100 * float64(done) / float64(total)
		s = fmt.Sprintf("[verify %s] %s / %s keys (%.1f%%)", el.Round(time.Second), commas(done), commas(total), pct)
		if rate > 0 && done < total {
			eta := time.Duration(float64(total-done) / rate * float64(time.Second))
			s += fmt.Sprintf(" ETA %s", eta.Round(time.Second))
		}
	}
	return s + fmt.Sprintf(" %s keys/s", commas(uint64(rate)))
}

func commas(n uint64) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
