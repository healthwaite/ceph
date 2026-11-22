package ramp

import (
	"strings"
	"testing"

	"kvrgw-perf/internal/config"
	"kvrgw-perf/internal/stats"
)

func lat(us uint64, n int) stats.Metric {
	var m stats.Metric
	for i := 0; i < n; i++ {
		m.Hist.AddBucket(stats.Index(us), 1)
		m.Count++
		m.SumMicros += us
	}
	return m
}

func baseCriteria() Criteria {
	return Criteria{MaxP99Ms: 50, MaxMissedPct: 0.1, MaxErrorPct: 0.1, MinAchievedPct: 99,
		MaxBacklogGrowthPct: 50, OutstandingCap: 8192}
}

func TestEvaluatePassAndEachFailure(t *testing.T) {
	good := func() Input {
		op := lat(10000, 60000) // 10 ms, 1,000 ops/s for 60 s
		return Input{Step: 2, Target: 1000, MeasureSecs: 60, Op: op, SendLag: lat(20, 60000),
			Service: lat(9000, 60000), OutstandingStart: 10, OutstandingEnd: 11, DriverBusyMax: 0.1}
	}
	s := Evaluate(good(), baseCriteria())
	if s.Verdict != "pass" || len(s.Failed) != 0 || s.AchievedPct < 99.9 || s.Scheduled != 60000 {
		t.Fatalf("good step: %+v", s)
	}
	cases := []struct {
		name string
		mod  func(*Input)
		want string
	}{
		{"achieved", func(in *Input) { in.Target = 1100 }, "achieved"},
		{"p99", func(in *Input) { in.Op = lat(80000, 60000) }, "p99"},
		{"missed", func(in *Input) { in.Op.Missed = 600 }, "missed"},
		{"errors", func(in *Input) { in.Op.Errors = 600 }, "errors"},
		{"backlog", func(in *Input) { in.OutstandingStart, in.OutstandingEnd = 10, 100 }, "backlog"},
	}
	for _, c := range cases {
		in := good()
		c.mod(&in)
		s := Evaluate(in, baseCriteria())
		if s.Verdict != "fail" || len(s.Failed) == 0 || !strings.Contains(strings.Join(s.Failed, ";"), c.want) {
			t.Errorf("%s: %+v", c.name, s)
		}
	}
	// A busy driver or significant send lag makes the result invalid.
	in := good()
	in.DriverBusyMax = 0.9
	if s := Evaluate(in, baseCriteria()); s.Verdict != "generator-limited" {
		t.Errorf("busy driver: %+v", s)
	}
	in = good()
	in.SendLag = lat(5000, 60000) // 5 ms of 10 ms
	if s := Evaluate(in, baseCriteria()); s.Verdict != "generator-limited" {
		t.Errorf("send lag: %+v", s)
	}
	// Near the outstanding cap: a note.
	in = good()
	cr := baseCriteria()
	cr.OutstandingCap = 16
	if s := Evaluate(in, cr); len(s.Notes) == 0 {
		t.Errorf("cap note missing: %+v", s)
	}
}

func TestSummarizeAndPlan(t *testing.T) {
	c := config.Defaults()
	c.RampStartRate, c.RampStepRate, c.RampMaxRate = 1000, 500, 2600
	c.RampWarmup, c.RampMeasure, c.ReportIntervalMs = "3s", "5500ms", 2000
	p, err := NewPlan(&c)
	if err != nil {
		t.Fatal(err)
	}
	if p.Warm != 2 || p.Measure != 3 || p.Len() != 5 {
		t.Fatalf("plan windows: %+v", p)
	}
	if p.Rate(0) != 1000 || p.Rate(3) != 2500 || !p.Exists(3) || p.Exists(4) {
		t.Fatal("rates / max rate")
	}
	if p.StartWindow(2) != 10 || p.LastWarmWindow(2) != 11 || p.LastWindow(2) != 14 || p.LastWarmWindow(0) != 1 {
		t.Fatal("windows")
	}
	c.RampStepRate = 0
	if c.RampRate(2) != 3000 {
		t.Fatal("step defaults to start")
	}
	r := Summarize(nil, "x")
	if r.MaxSustainableOpsPerSec != 0 {
		t.Fatal("empty")
	}
}
