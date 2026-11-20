package collect

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const clockTicksPerSec = 100

// ProcTicks parses /proc/<pid>/stat content and returns utime+stime in clock ticks.
// The comm field may contain spaces and parentheses, so parse after the last ')'.
func ProcTicks(stat string) (uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed stat")
	}
	f := strings.Fields(stat[i+1:])
	// f[0] is field 3 (state); utime is field 14 -> f[11], stime field 15 -> f[12].
	if len(f) < 13 {
		return 0, fmt.Errorf("short stat")
	}
	ut, err1 := strconv.ParseUint(f[11], 10, 64)
	st, err2 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("bad utime/stime")
	}
	return ut + st, nil
}

// CPUTimes is the aggregate line of /proc/stat plus the CPU count.
type CPUTimes struct {
	Busy, Total uint64
	NCPU        int
}

// ParseProcStat parses the contents of /proc/stat.
func ParseProcStat(s string) (CPUTimes, error) {
	var t CPUTimes
	found := false
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "cpu ") {
			f := strings.Fields(line)[1:]
			var v [8]uint64
			for i := 0; i < 8 && i < len(f); i++ {
				x, err := strconv.ParseUint(f[i], 10, 64)
				if err != nil {
					return t, err
				}
				v[i] = x
			}
			// user nice system idle iowait irq softirq steal
			t.Total = v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7]
			t.Busy = t.Total - v[3] - v[4]
			found = true
		} else if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			t.NCPU++
		}
	}
	if !found {
		return t, fmt.Errorf("no cpu line")
	}
	return t, nil
}

// WorkerCores converts a tick delta over dtSeconds into cores.
func WorkerCores(prevTicks, curTicks uint64, dtSeconds float64) float64 {
	if dtSeconds <= 0 || curTicks < prevTicks {
		return 0
	}
	return float64(curTicks-prevTicks) / (clockTicksPerSec * dtSeconds)
}

// SystemCores converts /proc/stat deltas into busy cores-equivalent.
func SystemCores(prev, cur CPUTimes) float64 {
	dt := cur.Total - prev.Total
	if cur.Total < prev.Total || dt == 0 || cur.Busy < prev.Busy {
		return 0
	}
	return float64(cur.Busy-prev.Busy) / float64(dt) * float64(cur.NCPU)
}

func readProcTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return ProcTicks(string(b))
}

func readSystem() (CPUTimes, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPUTimes{}, err
	}
	return ParseProcStat(string(b))
}
