// Package controller orchestrates one perf invocation: spawn workers, Init, RunBenchmark,
// Verify, Cleanup, aggregating metrics into the results directory.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "kvrgw-perf/gen/perf/v1"
	"kvrgw-perf/internal/collect"
	"kvrgw-perf/internal/config"
	"kvrgw-perf/internal/local"
	"kvrgw-perf/internal/results"
	"kvrgw-perf/internal/stats"
)

// Options for one invocation.
type Options struct {
	Command  string
	Cfg      config.Config
	Warnings []string
	RunDir   string // "" => default perf-results/<ts>-<command>
	NoVerify bool
	Launcher local.Launcher // nil => caller must supply one
	Out      io.Writer      // terminal output (stdout)
}

type workerConn struct {
	addr   string
	pid    int
	conn   *grpc.ClientConn
	client pb.WorkerClient
}

// Run executes the invocation and returns the process exit code (0 ok, 1 failure).
func Run(ctx context.Context, o Options) int {
	inv := &invocation{o: o, out: o.Out}
	if inv.out == nil {
		inv.out = os.Stdout
	}
	return inv.run(ctx)
}

type invocation struct {
	o   Options
	out io.Writer
	dir *results.Dir
	ev  *results.Events
	lg  *log.Logger

	benchID  string
	startS   int64
	workers  []*workerConn
	failures []string // human-readable reasons
	mu       sync.Mutex

	// metrics
	metricsCSV, histCSV, serverCSV *results.CSV
	runStartMs, intervalMs         int64
	totals                         map[string]*stats.Metric
	cum                            map[string][2]uint64
	seenOps                        map[string]bool
	windows                        int
	lastServer                     map[string]uint64
	verifySum                      *results.VerifySummary
	errorsCSV                      *results.CSV
	errDescs                       map[string]string
	workerSums                     []*pb.RunSummary
	benchEndMs                     int64
}

func (v *invocation) fail(format string, a ...any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	msg := fmt.Sprintf(format, a...)
	v.failures = append(v.failures, msg)
	v.lg.Printf("ERROR %s", msg)
	fmt.Fprintf(os.Stderr, "ERROR: %s\n", msg)
}

func (v *invocation) warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	v.lg.Printf("WARN %s", msg)
	fmt.Fprintf(os.Stderr, "WARN: %s\n", msg)
}

func (v *invocation) run(ctx context.Context) int {
	now := time.Now()
	v.startS = now.Unix()
	v.benchID = fmt.Sprintf("%s-%d", v.o.Command, now.UnixNano())
	var err error
	if v.dir, err = results.NewRunDir(v.o.RunDir, v.o.Command, now); err != nil {
		fmt.Fprintln(os.Stderr, "cannot create run dir:", err)
		return 1
	}
	lf, err := os.Create(v.dir.File("controller.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create controller.log:", err)
		return 1
	}
	defer lf.Close()
	v.lg = log.New(lf, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	if v.ev, err = v.dir.OpenEvents(); err != nil {
		v.fail("events.csv: %v", err)
		return 1
	}
	defer v.ev.Close()
	v.ev.At(now.UnixMilli(), "invocation_start")
	fmt.Fprintf(v.out, "kvrgw-perf %s -> %s\n", v.o.Command, v.dir.Path)
	for _, w := range v.o.Warnings {
		v.warn("%s", w)
	}

	cfg := v.o.Cfg
	if b, err := cfg.ResolvedJSON(); err == nil {
		os.WriteFile(v.dir.File("config.resolved.json"), b, 0o644)
	}

	// Master context: cancelled on unexpected worker exit.
	mctx, cancelM := context.WithCancel(context.Background())
	defer cancelM()
	go func() {
		select {
		case err := <-v.o.Launcher.Exited():
			v.fail("%v", err)
			cancelM()
		case <-mctx.Done():
		}
	}()
	// A signal before the benchmark starts aborts the invocation.
	benchStarted := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-benchStarted:
			default:
				v.fail("interrupted")
				cancelM()
			}
		case <-mctx.Done():
		}
	}()

	// Collectors that don't need workers.
	cctx, stopCollectors := context.WithCancel(context.Background())
	var collectorsWG sync.WaitGroup
	v.startFDB(cctx, &collectorsWG)

	exit := v.execute(ctx, mctx, cctx, &collectorsWG, benchStarted)

	stopCollectors()
	collectorsWG.Wait()
	v.o.Launcher.Stop()
	v.ev.Now("invocation_end")
	v.writeSummary(exit)
	return exit
}

func (v *invocation) startFDB(cctx context.Context, wg *sync.WaitGroup) {
	cfg := v.o.Cfg
	if !cfg.FdbStats {
		return
	}
	s := &collect.FDBSampler{Path: cfg.FdbcliPath, ClusterFile: cfg.FdbClusterFile,
		Interval: time.Duration(cfg.FdbSampleIntervalMs) * time.Millisecond, Logf: v.lg.Printf}
	raw, err := s.Status(cctx)
	if err == nil {
		_, _, err = collect.ParseStatus(raw)
	}
	if err != nil {
		v.warn("FDB stats disabled: fdbcli status failed: %v", err)
		return
	}
	os.WriteFile(v.dir.File("fdb_status_start.json"), raw, 0o644)
	cl, e1 := v.dir.OpenCSV("fdb_cluster.csv", results.FDBClusterHeader...)
	pr, e2 := v.dir.OpenCSV("fdb_process.csv", results.FDBProcessHeader...)
	if e1 != nil || e2 != nil {
		v.warn("cannot create FDB csv files: %v %v", e1, e2)
		return
	}
	s.Cluster, s.Process = cl, pr
	// Per-process CPU for every process is optional: the run works without it.
	cpu, e3 := v.dir.OpenCSV("fdb_cpu.csv", results.FDBCPUHeader...)
	if e3 != nil {
		v.warn("cannot create fdb_cpu.csv: %v", e3)
	} else {
		s.CPU = cpu
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Run(cctx)
		if n := s.Failures.Load(); n > 0 {
			v.warn("%d FDB status samples failed (%d ok)", n, s.Samples.Load())
		}
		cl.Close()
		pr.Close()
		if cpu != nil {
			cpu.Close()
		}
	}()
}

func (v *invocation) execute(sigCtx, mctx, cctx context.Context, wg *sync.WaitGroup, benchStarted chan struct{}) int {
	cfg := v.o.Cfg
	ws, err := v.o.Launcher.Start(mctx, cfg.WorkerCount)
	if err != nil {
		v.fail("starting workers: %v", err)
		return 1
	}
	var pids []int
	for _, w := range ws {
		conn, err := grpc.NewClient(w.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			v.fail("dial %s: %v", w.Addr, err)
			return 1
		}
		defer conn.Close()
		v.workers = append(v.workers, &workerConn{addr: w.Addr, pid: w.PID, conn: conn, client: pb.NewWorkerClient(conn)})
		if w.PID != 0 {
			pids = append(pids, w.PID)
		}
	}
	if len(pids) == len(ws) {
		if cpu, err := v.dir.OpenCSV("cpu.csv", results.CPUHeader...); err == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collect.RunCPUSampler(cctx, cpu, pids, time.Duration(cfg.CpuSampleIntervalMs)*time.Millisecond)
				cpu.Close()
			}()
		}
	}

	cfgJSON, err := cfg.WorkerJSON()
	if err != nil {
		v.fail("config: %v", err)
		return 1
	}

	// ---- Init ----
	fmt.Fprintf(v.out, "initialising %d worker(s) x %d thread(s)...\n", cfg.WorkerCount, cfg.ThreadsPerWorker)
	ictx, cancelI := context.WithTimeout(mctx, 5*time.Minute)
	errs := v.forAll(func(i int, w *workerConn) error {
		st, err := w.client.Init(ictx, &pb.InitRequest{
			Operation: v.o.Command, ConfigJson: cfgJSON, WorkerIndex: int32(i),
			WorkerCount: int32(cfg.WorkerCount), BenchmarkId: v.benchID, RunStartUnixS: v.startS,
		}, grpc.WaitForReady(true))
		if err != nil {
			return err
		}
		return drainTerminal(st, func(ev *pb.PhaseEvent) error {
			if ev.Error != "" {
				return fmt.Errorf("%s", ev.Error)
			}
			return nil
		})
	})
	cancelI()
	if v.reportErrs("init", errs) {
		v.cleanup(mctx)
		return 1
	}
	v.ev.Now("init_done")

	// ---- RunBenchmark ----
	summaries, ok := v.runBenchmark(sigCtx, mctx, benchStarted)
	v.workerSums = summaries
	interrupted := sigCtx.Err() != nil
	exit := 0
	if !ok || len(v.failures) > 0 {
		exit = 1
	}

	// ---- Verify ----
	if exit == 0 && !interrupted && !v.o.NoVerify && v.opHasVerify() {
		if !v.verify(mctx, summaries) {
			exit = 1
		}
	} else if interrupted {
		fmt.Fprintln(v.out, "interrupted: skipping verify")
		if len(v.failures) == 0 {
			v.fail("interrupted by signal")
		}
		exit = 1
	}
	v.cleanup(mctx)
	return exit
}

func (v *invocation) opHasVerify() bool { return true }

func (v *invocation) cleanup(mctx context.Context) {
	cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	v.forAll(func(i int, w *workerConn) error {
		st, err := w.client.Cleanup(cctx, &pb.CleanupRequest{BenchmarkId: v.benchID})
		if err != nil {
			return err
		}
		return drainTerminal(st, func(*pb.PhaseEvent) error { return nil })
	})
}

type eventStream interface {
	Recv() (*pb.PhaseEvent, error)
}

// drainTerminal reads a server stream to the end, invoking fn on the last event.
func drainTerminal(st eventStream, fn func(*pb.PhaseEvent) error, onProgress ...func(*pb.PhaseEvent)) error {
	var last *pb.PhaseEvent
	for {
		ev, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if ev.VerifyProgress != nil {
			for _, f := range onProgress {
				f(ev)
			}
			continue // periodic event, not the terminal one
		}
		last = ev
	}
	if last == nil {
		return fmt.Errorf("worker closed stream without a terminal event")
	}
	return fn(last)
}

// forAll runs fn on every worker in parallel and returns per-worker errors.
func (v *invocation) forAll(fn func(i int, w *workerConn) error) []error {
	errs := make([]error, len(v.workers))
	var wg sync.WaitGroup
	for i, w := range v.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fn(i, w)
		}()
	}
	wg.Wait()
	return errs
}

func (v *invocation) reportErrs(phase string, errs []error) bool {
	bad := false
	for i, e := range errs {
		if e != nil {
			bad = true
			v.fail("%s failed on worker %d: %v", phase, i, e)
		}
	}
	return bad
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

func (v *invocation) writeSummary(exit int) {
	sum := v.buildSummary(exit)
	b, _ := json.MarshalIndent(sum, "", "  ")
	os.WriteFile(v.dir.File("summary.json"), b, 0o644)
	v.printFinal(sum)
}
