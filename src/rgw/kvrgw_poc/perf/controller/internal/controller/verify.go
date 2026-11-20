package controller

import (
	"context"
	"fmt"
	"sort"
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
	t0 := time.Now()
	res := make([]*pb.PhaseEvent, len(v.workers))
	errs := v.forAll(func(i int, w *workerConn) error {
		st, err := w.client.Verify(mctx, &pb.VerifyRequest{BenchmarkId: v.benchID, ThreadCounts: counts})
		if err != nil {
			return err
		}
		return drainTerminal(st, func(ev *pb.PhaseEvent) error {
			res[i] = ev
			return nil
		})
	})
	v.ev.Now("verify_end")
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
