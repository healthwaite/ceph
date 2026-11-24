package controller

import (
	"strings"
	"testing"
	"time"

	pb "kvrgw-perf/gen/perf/v1"
)

func TestVerifyProgressLine(t *testing.T) {
	t0 := time.Unix(1000, 0)
	p := newVerifyProgress(2, t0)
	p.update(&pb.PhaseEvent{VerifyProgress: &pb.VerifyProgress{WorkerIndex: 0, KeysChecked: 250, KeysTotal: 500}})
	p.update(&pb.PhaseEvent{VerifyProgress: &pb.VerifyProgress{WorkerIndex: 1, KeysChecked: 250, KeysTotal: 500}})
	got := p.line(t0.Add(10 * time.Second))
	for _, want := range []string{"[verify 10s]", "500 / 1,000 keys (50.0%)", "ETA 10s", "50 keys/s"} {
		if !strings.Contains(got, want) {
			t.Errorf("line %q missing %q", got, want)
		}
	}
	// An unknown total on any worker drops the percentage.
	p.update(&pb.PhaseEvent{VerifyProgress: &pb.VerifyProgress{WorkerIndex: 1, KeysChecked: 250}})
	got = p.line(t0.Add(10 * time.Second))
	if strings.Contains(got, "%") || !strings.Contains(got, "500 keys checked") {
		t.Errorf("unknown total: got %q", got)
	}
}

func TestProgressLine(t *testing.T) {
	parts := []string{"list_objects 5 ops/s", "delete_multi 4 ops/s"}
	if got := progressLine("run-put-object", "10s", parts); got != "[t=10s] list_objects 5 ops/s | delete_multi 4 ops/s" {
		t.Fatalf("single line: %q", got)
	}
	if got := progressLine("run-list-delete-multi", "130s", parts); got != "[t=130s]\n\tlist_objects 5 ops/s\n\tdelete_multi 4 ops/s" {
		t.Fatalf("multi line: %q", got)
	}
}
