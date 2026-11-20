// Package local launches worker processes on this host (local mode).
package local

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Worker is a running (or reachable) worker.
type Worker struct {
	Addr string
	PID  int // 0 if not a local process
}

// Launcher abstracts how workers are made available, so that a future
// "connect to given addresses" implementation is a drop-in.
type Launcher interface {
	// Start returns n workers; each accepts connections on Addr once Start returns
	// (callers still use gRPC wait-for-ready since the runtime may need time to boot).
	Start(ctx context.Context, n int) ([]Worker, error)
	// Exited reports the first unexpected worker exit.
	Exited() <-chan error
	Stop()
}

// Local spawns kvrgw-perf-worker child processes.
type Local struct {
	Binary   string
	BasePort int
	RunDir   string
	CPUs     string // optional pool, e.g. "0-15" or "0,2,4-7"
	// KvrgwConfig is the synthesized runtime config (KVRGW_CONFIG_FILE) and ExtraEnv extra
	// variables (e.g. KVRGW_BATCH_*) for every worker.
	KvrgwConfig string
	ExtraEnv    []string
	Grace       time.Duration

	mu       sync.Mutex
	cmds     []*exec.Cmd
	socks    []string
	logs     []*os.File
	stopping bool
	exited   chan error
}

func (l *Local) Exited() <-chan error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.exited == nil {
		l.exited = make(chan error, 64)
	}
	return l.exited
}

// ParseCPUList parses "0-3,8,10-11".
func ParseCPUList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, e1 := strconv.Atoi(a)
			hi, e2 := strconv.Atoi(b)
			if e1 != nil || e2 != nil || lo > hi || lo < 0 {
				return nil, fmt.Errorf("bad cpu range %q", part)
			}
			for c := lo; c <= hi; c++ {
				out = append(out, c)
			}
		} else {
			c, err := strconv.Atoi(part)
			if err != nil || c < 0 {
				return nil, fmt.Errorf("bad cpu %q", part)
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// SplitCPUs divides the pool evenly (contiguous chunks; remainder to the first workers).
// If there are fewer CPUs than workers, workers share (wrap around).
func SplitCPUs(pool []int, n int) [][]int {
	out := make([][]int, n)
	if len(pool) == 0 {
		return out
	}
	if len(pool) < n {
		for i := range out {
			out[i] = []int{pool[i%len(pool)]}
		}
		return out
	}
	base, extra, pos := len(pool)/n, len(pool)%n, 0
	for i := 0; i < n; i++ {
		c := base
		if i < extra {
			c++
		}
		out[i] = pool[pos : pos+c]
		pos += c
	}
	return out
}

func cpuListString(c []int) string {
	s := make([]string, len(c))
	for i, v := range c {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

func (l *Local) Start(ctx context.Context, n int) ([]Worker, error) {
	l.Exited() // make sure the channel exists
	var split [][]int
	if l.CPUs != "" {
		pool, err := ParseCPUList(l.CPUs)
		if err != nil {
			return nil, err
		}
		split = SplitCPUs(pool, n)
	}
	var ws []Worker
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", l.BasePort+i)
		args := []string{"--listen", addr}
		name := l.Binary
		if split != nil && len(split[i]) > 0 {
			args = append([]string{"-c", cpuListString(split[i]), l.Binary}, args...)
			name = "taskset"
		}
		cmd := exec.Command(name, args...)
		sock := filepath.Join(os.TempDir(), fmt.Sprintf("kvrgw-perf-%d-%d.sock", os.Getpid(), i))
		cmd.Env = append(os.Environ(), l.ExtraEnv...)
		if l.KvrgwConfig != "" {
			cmd.Env = append(cmd.Env, "KVRGW_CONFIG_FILE="+l.KvrgwConfig)
		}
		cmd.Env = append(cmd.Env,
			"KVRGW_INSTANCE_ID="+strconv.Itoa(i),
			"KVRGW_ADMIN_SOCKET="+sock)
		lf, err := os.Create(filepath.Join(l.RunDir, fmt.Sprintf("worker-%d.log", i)))
		if err != nil {
			l.Stop()
			return nil, err
		}
		cmd.Stdout, cmd.Stderr = lf, lf
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			lf.Close()
			l.Stop()
			return nil, fmt.Errorf("start worker %d (%s): %w", i, name, err)
		}
		l.mu.Lock()
		l.cmds = append(l.cmds, cmd)
		l.logs = append(l.logs, lf)
		l.socks = append(l.socks, sock)
		l.mu.Unlock()
		ws = append(ws, Worker{Addr: addr, PID: cmd.Process.Pid})
		go func(i int, cmd *exec.Cmd) {
			err := cmd.Wait()
			l.mu.Lock()
			stopping := l.stopping
			l.mu.Unlock()
			if !stopping {
				l.exited <- fmt.Errorf("worker %d exited unexpectedly: %v (see worker-%d.log)", i, err, i)
			}
		}(i, cmd)
	}
	return ws, nil
}

// Stop sends SIGTERM, waits Grace (default 15s), then SIGKILLs.
func (l *Local) Stop() {
	l.mu.Lock()
	l.stopping = true
	cmds := append([]*exec.Cmd(nil), l.cmds...)
	l.mu.Unlock()
	grace := l.Grace
	if grace == 0 {
		grace = 15 * time.Second
	}
	for _, c := range cmds {
		if c.Process != nil {
			c.Process.Signal(syscall.SIGTERM)
		}
	}
	deadline := time.Now().Add(grace)
	for _, c := range cmds {
		for time.Now().Before(deadline) && alive(c) {
			time.Sleep(50 * time.Millisecond)
		}
		if alive(c) {
			c.Process.Kill()
		}
	}
	l.mu.Lock()
	for _, f := range l.logs {
		f.Close()
	}
	for _, s := range l.socks {
		os.Remove(s)
	}
	l.cmds, l.logs, l.socks = nil, nil, nil
	l.mu.Unlock()
}

func alive(c *exec.Cmd) bool {
	if c.Process == nil {
		return false
	}
	return c.Process.Signal(syscall.Signal(0)) == nil && (c.ProcessState == nil || !c.ProcessState.Exited())
}
