package cpufrequency

/*
#cgo LDFLAGS: -L${SRCDIR}
#include "cpu_frequency.h"
int duration;
*/
import "C"

import (
	"errors"
	"strconv"
	"time"

	"github.com/ricky1993/sys-insight/pkg/module"
	"github.com/ricky1993/sys-insight/pkg/utils"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

type CPUFrequency struct {
	duration int64
	period   int64
	stopCh   chan struct{}
	channel  chan []byte
}

const Name = "cpufrequency"

var _ module.BPFModule = &CPUFrequency{}

var (
	freqInitError = errors.New("pqos init error")
)

func (cf *CPUFrequency) Init() error {
	if ret := C.monitor_init(); ret != 0 {
		klog.Errorf("[Module] module %s Init error", cf.Name)
		return freqInitError
	}
	return nil
}

func (cf *CPUFrequency) sample() {
	cf.channel <- []byte{}
}

func (cf *CPUFrequency) Start() error {
	klog.Infof("[Module] start module %s", cf.Name())

	go wait.Until(cf.sample, time.Duration(cf.period)*time.Second, cf.stopCh)
	return nil
}

func (cf *CPUFrequency) Stop() error {
	klog.Infof("[Module] stop module %s", cf.Name())
	close(cf.stopCh)
	C.free_all_buffers()
	return nil
}

func (cf *CPUFrequency) Name() string {
	return Name
}
func (cf *CPUFrequency) GetDataChannel() <-chan []byte {
	return cf.channel
}

func (cf *CPUFrequency) SetSinkChannel(sc chan<- interface{}) error {
	return nil
}

func (cf *CPUFrequency) ProcessEvent([]byte) (interface{}, error) {
	max_core := utils.CountCPUCores()
	klog.V(10).Infof("[Module] process start %s, duration: %d", cf.Name(), cf.duration)
	C.duration = C.int(cf.duration)
	C.monitor_loop(C.duration, 1)

	dataMaps := make(map[string]*module.BasicData)
	for i := 0; i < max_core; i++ {
		name := "cpu" + strconv.Itoa(i)
		dataMaps[name] = &module.BasicData{
			Name:  name,
			Value: 0,
		}
	}
	getFreqData(dataMaps)
	// send Data
	for _, v := range dataMaps {
		klog.Infof("[Module] module %s %s frequency: %f", cf.Name(), v.Name, v.Value)
	}
	return nil, nil
}

func getFreqData(dataMap map[string]*module.BasicData) error {
	max_core := utils.CountCPUCores()
	for i := 0; i < max_core; i++ {
		name := "cpu" + strconv.Itoa(i)
		dataMap[name].Value = float64(C.output[i])
	}

	return nil
}

func New() module.BPFModule {
	return &CPUFrequency{
		stopCh:   make(chan struct{}),
		channel:  make(chan []byte, 0),
		period:   1,
		duration: 1,
	}
}
