package provider

import (
	"github.com/ricky1993/sys-insight/cmd/agent/app/config"
	"github.com/ricky1993/sys-insight/pkg/module"
	"github.com/ricky1993/sys-insight/pkg/module/cpufrequency"
)

type Registry map[string]module.BPFModule

func NewRegistry(cc config.CompletedConfig) Registry {
	defaultConfig := getDefaultConfig()
	// apply config enable & disable module
	moduleRegistry := make(map[string]module.BPFModule)
	moduleRegistry[cpufrequency.Name] = cpufrequency.New()
	registry := make(map[string]module.BPFModule)
	for _, name := range defaultConfig {
		registry[name] = moduleRegistry[name]
	}
	return registry
}

func getDefaultConfig() []string {
	return []string{
		cpufrequency.Name,
	}
}
