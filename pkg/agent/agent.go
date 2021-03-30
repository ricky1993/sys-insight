package agent

import (
	"sync"

	"github.com/ricky1993/sys-insight/cmd/agent/app/config"
	"github.com/ricky1993/sys-insight/pkg/module"
	"github.com/ricky1993/sys-insight/pkg/provider"

	"k8s.io/klog/v2"
)

type Agent struct {
	modules []module.BPFModule
	wg      sync.WaitGroup
}

func NewAgent(cc config.CompletedConfig) (*Agent, error) {
	registry := provider.NewRegistry(cc)
	agent := &Agent{
		modules: make([]module.BPFModule, 0, len(registry)),
	}

	for _, module := range registry {
		agent.modules = append(agent.modules, module)
		err := module.Init()
		if err != nil {
			klog.Errorf("[agent] failed to init module %s, error: %v", module.Name(), err)
			return nil, err
		}
	}
	return agent, nil
}

func (agent *Agent) Start() {
	for _, m := range agent.modules {
		err := m.Start()
		if err != nil {
			klog.Errorf("[agent] failed to start module %s, error: %v", m.Name(), err)
		} else {
			go func(m module.BPFModule) {
				channel := m.GetDataChannel()
				for {
					data := <-channel
					m.ProcessEvent(data)
				}
			}(m)
			agent.wg.Add(1)
		}
	}
}

func (agent *Agent) Stop() {
	for _, m := range agent.modules {
		err := m.Stop()
		if err != nil {
			klog.Errorf("[agent] failed to stop module %s, error: %v", m.Name(), err)
		}
		agent.wg.Done()
	}
}
