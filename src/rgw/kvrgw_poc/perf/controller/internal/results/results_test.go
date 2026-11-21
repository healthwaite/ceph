package results

import (
	"encoding/csv"
	"os"
	"testing"
	"time"
)

func TestCSVWriterAndRunDir(t *testing.T) {
	d, err := NewRunDir(t.TempDir()+"/x", "load", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.OpenCSV("metrics.csv", MetricsHeader...)
	if err != nil {
		t.Fatal(err)
	}
	c.Row("1", "0", "put_object", "5", "0", "5.000", "", "", "", "", "", "", "5", "0", "0", "0")
	// Flushed per row: readable before Close.
	f, _ := os.Open(d.File("metrics.csv"))
	recs, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil || len(recs) != 2 || recs[0][0] != "unix_ts_ms" || recs[1][2] != "put_object" {
		t.Fatalf("%v %v", recs, err)
	}
	c.Close()
	ev, _ := d.OpenEvents()
	ev.At(1700000000123, "benchmark_start")
	ev.Close()
	b, _ := os.ReadFile(d.File("events.csv"))
	if string(b) != "unix_ts_ms,event\n1700000000123,benchmark_start\n" {
		t.Fatalf("%q", b)
	}
}
