package options

import (
	"github.com/ricky1993/sys-insight/cmd/agent/app/config"

	cliflag "k8s.io/component-base/cli/flag"
)

type Options struct {
	// ConfigFile is the location of the configuration file.
	ConfigFile string

	// WriteConfigTo is the path where the default configuration will be written.
	WriteConfigTo string
}

// NewOptions returns default dispatcher app options.
func NewOptions() (*Options, error) {
	//TODO: we can set default config value here, if it is necessary in the future.
	o := &Options{}

	return o, nil
}

func (o *Options) Flags() (nfs cliflag.NamedFlagSets) {
	fs := nfs.FlagSet("misc")
	fs.StringVar(&o.ConfigFile, "config", o.ConfigFile, "The path to the configuration file. Flags override values in this file.")
	fs.StringVar(&o.WriteConfigTo, "write-config-to", o.WriteConfigTo, "If set, write the configuration values to this file and exit.")

	return nfs
}

// ApplyTo applies the agent options to the given agent app configuration.
func (o *Options) ApplyTo(c *config.Config) error {
	//TODO: implement dispatcher config if necessary.
	return nil
}

// Validate validates all the required options.
func (o *Options) Validate() []error {
	var errs []error
	//TODO: validation
	return errs
}

func (o *Options) Config() (*config.Config, error) {
	c := &config.Config{}
	if err := o.ApplyTo(c); err != nil {
		return nil, err
	}
	return c, nil
}
