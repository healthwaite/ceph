package local

import (
	"reflect"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	got, err := ParseCPUList("0-2, 5,7-8")
	if err != nil || !reflect.DeepEqual(got, []int{0, 1, 2, 5, 7, 8}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"a", "3-1", "-2", "1-x"} {
		if _, err := ParseCPUList(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestSplitCPUs(t *testing.T) {
	pool := []int{0, 1, 2, 3, 4, 5, 6}
	got := SplitCPUs(pool, 3)
	want := [][]int{{0, 1, 2}, {3, 4}, {5, 6}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	got = SplitCPUs([]int{0, 1}, 3)
	if !reflect.DeepEqual(got, [][]int{{0}, {1}, {0}}) {
		t.Fatalf("%v", got)
	}
	if SplitCPUs(nil, 2)[0] != nil {
		t.Fatal("empty pool should give no pinning")
	}
}
