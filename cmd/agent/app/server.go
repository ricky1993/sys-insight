package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/ricky1993/sys-insight/cmd/agent/app/config"
	"github.com/ricky1993/sys-insight/cmd/agent/app/options"
	"github.com/ricky1993/sys-insight/pkg/agent"

	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/term"
	"k8s.io/klog/v2"
)

func NewAgentCommand() *cobra.Command {
	opts, err := options.NewOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to initialize command options: %v\n", err)
		os.Exit(1)
	}
	cmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			if err := runCommand(cmd, opts, args); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
	}
	fs := cmd.Flags()
	namedFlagSets := opts.Flags()
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name())
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), namedFlagSets, cols)
		return nil
	})
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), namedFlagSets, cols)
	})
	cmd.MarkFlagFilename("config", "yaml", "yml", "json")

	return cmd
}

func runCommand(cmd *cobra.Command, opts *options.Options, args []string) error {
	if len(args) != 0 {
		fmt.Fprint(os.Stderr, "arguments are not supported\n")
	}

	if errs := opts.Validate(); len(errs) > 0 {
		return utilerrors.NewAggregate(errs)
	}

	if len(opts.WriteConfigTo) > 0 {
		c := &config.Config{}
		if err := opts.ApplyTo(c); err != nil {
			return err
		}
		klog.Infof("Wrote configuration to: %s\n", opts.WriteConfigTo)
		return nil
	}

	c, err := opts.Config()
	if err != nil {
		return err
	}
	// Get the completed config
	cc := c.Complete()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return Run(ctx, cc)
}

func Run(ctx context.Context, cc config.CompletedConfig) error {
	agent, err := agent.NewAgent(cc)
	if err != nil {
		klog.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	agent.Start()
	signal := <-sig
	klog.Infof("killed by signal %v", signal)
	agent.Stop()
	return nil
}
