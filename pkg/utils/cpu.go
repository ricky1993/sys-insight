package utils

import (
	"runtime"
	"strings"
)

var (
	cpuCores int = 0
)

func CountCPUCores() int {
	if cpuCores > 0 {
		return cpuCores
	}
	cores := 0
	lines, err := ReadLines("/proc/cpuinfo")
	if err != nil {
		cpuCores = runtime.NumCPU()
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}
	cpuCores = cores
	return cpuCores
}
