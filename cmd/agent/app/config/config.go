package config

type Config struct{}

type completedConfig struct {
	*Config
}

type CompletedConfig struct {
	*completedConfig
}

func (c *Config) Complete() CompletedConfig {
	cc := completedConfig{c}
	return CompletedConfig{&cc}
}
