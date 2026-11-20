package stats

import (
	"encoding/json"
	"math"
	"os"
	"testing"

	pb "kvrgw-perf/gen/perf/v1"
)

func TestHistogramVector(t *testing.T) {
	b, err := os.ReadFile("../../../proto/testdata/histogram.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		NumBuckets int `json:"num_buckets"`
		Index      []struct {
			Micros uint64 `json:"micros"`
			Bucket int    `json:"bucket"`
		} `json:"index"`
		Midpoint []struct {
			Bucket int    `json:"bucket"`
			Mid    uint64 `json:"mid"`
		} `json:"midpoint"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.NumBuckets != NumBuckets {
		t.Fatalf("num buckets %d", v.NumBuckets)
	}
	for _, e := range v.Index {
		if got := Index(e.Micros); got != e.Bucket {
			t.Errorf("Index(%d)=%d want %d", e.Micros, got, e.Bucket)
		}
	}
	for _, e := range v.Midpoint {
		if got := Midpoint(e.Bucket); got != e.Mid {
			t.Errorf("Midpoint(%d)=%d want %d", e.Bucket, got, e.Mid)
		}
	}
}

func TestMergeAndQuantiles(t *testing.T) {
	var a, b Hist
	for i := 0; i < 90; i++ {
		a.AddBucket(Index(100), 1)
	}
	for i := 0; i < 10; i++ {
		b.AddBucket(Index(10000), 1)
	}
	a.Merge(b)
	if a.Total() != 100 {
		t.Fatal(a.Total())
	}
	if q := a.Quantile(0.5); q != Midpoint(Index(100)) {
		t.Fatalf("p50 %d", q)
	}
	if q := a.Quantile(0.99); q != Midpoint(Index(10000)) {
		t.Fatalf("p99 %d", q)
	}
	if a.Max() != Midpoint(Index(10000)) {
		t.Fatal("max")
	}
	var empty Hist
	if empty.Quantile(0.5) != 0 || empty.Max() != 0 {
		t.Fatal("empty hist")
	}
}

func TestErrorCodesMergeAndFormat(t *testing.T) {
	a := FromProto(&pb.OpStats{Count: 1, Errors: 3, ErrorCodes: map[string]uint64{"KVRGW_ERR_TXN_CONFLICT": 2, "KVRGW_ERR_NO_SUCH_BUCKET": 1}})
	b := FromProto(&pb.OpStats{Errors: 2, ErrorCodes: map[string]uint64{"KVRGW_ERR_TXN_CONFLICT": 2}})
	a.Merge(&b)
	if a.Errors != 5 || a.ErrorCodes["KVRGW_ERR_TXN_CONFLICT"] != 4 || a.ErrorCodes["KVRGW_ERR_NO_SUCH_BUCKET"] != 1 {
		t.Fatalf("%+v", a)
	}
	if got := FormatErrorCodes(a.ErrorCodes); got != "TXN_CONFLICT x4, NO_SUCH_BUCKET x1" {
		t.Fatalf("%q", got)
	}
	if FormatErrorCodes(nil) != "" {
		t.Fatal("empty")
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]float64{10, 10, 10, 10, 10, 10, 10, 10, 10, 20}, 10)
	if s.Median != 10 || s.Min != 10 || s.Max != 20 || math.Abs(s.Avg-11) > 1e-9 {
		t.Fatalf("%+v", s)
	}
	if s.DevPct != 10 { // only the 20 deviates by >10%
		t.Fatalf("dev %v", s.DevPct)
	}
	if z := Summarize([]float64{0, 0, 0}, 10); z.DevPct != 0 {
		t.Fatal("median 0 => dev 0")
	}
	if e := Summarize(nil, 10); e.N != 0 {
		t.Fatal("empty")
	}
}

func progress(window int64, put uint64, srv uint64) *pb.ProgressReport {
	return &pb.ProgressReport{
		Window: window, WindowDurationNs: 1e9,
		WindowStats: []*pb.OpStats{{OperationType: "put_object", Count: put, SumMicros: put * 100,
			Latency: &pb.Histogram{BucketIndex: []uint32{100}, BucketCount: []uint64{put}}}},
		ServerStats: &pb.ServerStats{BatchCommits: srv},
	}
}

func TestAggregatorAcrossWorkers(t *testing.T) {
	a := NewAggregator(2)
	if got := a.Add(0, progress(0, 10, 5)); len(got) != 0 {
		t.Fatal("window 0 must wait for worker 1")
	}
	got := a.Add(1, progress(0, 20, 7))
	if len(got) != 1 || got[0].Ops["put_object"].Count != 30 {
		t.Fatalf("%+v", got)
	}
	if got[0].Server["batch.commits"] != 12 {
		t.Fatalf("server sum %v", got[0].Server)
	}
	// worker 0 advances to windows 1 and 2; worker 1 only 1 -> release up to 1
	a.Add(0, progress(1, 1, 6))
	a.Add(0, progress(2, 1, 6))
	got = a.Add(1, progress(1, 2, 8))
	if len(got) != 1 || got[0].Index != 1 || got[0].Ops["put_object"].Count != 3 {
		t.Fatalf("%+v", got)
	}
	// worker 1 finishes: window 2 (only worker 0) is released.
	got = a.Finish(1)
	if len(got) != 1 || got[0].Index != 2 {
		t.Fatalf("%+v", got)
	}
	if got = a.Finish(0); len(got) != 0 {
		t.Fatal("nothing left")
	}
}

func TestMsFormatting(t *testing.T) {
	for in, want := range map[float64]string{
		0: "0", 5772: "5.77", 10070: "10.1", 9816: "9.82", 234: "0.234", 23.4: "0.0234",
		123456: "123", 1234567: "1,235", 999: "0.999", 100000: "100",
	} {
		if got := MsNum(in); got != want {
			t.Errorf("MsNum(%v)=%q want %q", in, got, want)
		}
	}
	if Ms(5772) != "5.77ms" {
		t.Fatal(Ms(5772))
	}
}
