package collect

import (
	"context"
	"fmt"
	"time"

	"kvrgw-perf/internal/results"
)

// RunCPUSampler samples worker-process and whole-host CPU every interval until ctx ends,
// writing cpu.csv rows (source = worker-<i> or system). Local mode only.
func RunCPUSampler(ctx context.Context, out *results.CSV, pids []int, interval time.Duration) {
	prevT := make([]uint64, len(pids))
	for i, pid := range pids {
		prevT[i], _ = readProcTicks(pid)
	}
	prevSys, _ := readSystem()
	prevAt := time.Now()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tk.C:
			dt := now.Sub(prevAt).Seconds()
			prevAt = now
			ms := now.UnixMilli()
			for i, pid := range pids {
				cur, err := readProcTicks(pid)
				if err != nil {
					continue
				}
				out.Row(results.I(ms), fmt.Sprintf("worker-%d", i), results.F(WorkerCores(prevT[i], cur, dt)))
				prevT[i] = cur
			}
			if cur, err := readSystem(); err == nil {
				out.Row(results.I(ms), "system", results.F(SystemCores(prevSys, cur)))
				prevSys = cur
			}
		}
	}
}
