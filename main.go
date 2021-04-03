//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// Default subid range required by sysbox
var subidRangeSize uint64 = 65536

const (
	usage = `Sysbox manager daemon

The Sysbox manager daemon's main job is to provide services to other
Sysbox components (e.g., sysbox-runc).`
)

// Globals to be populated at build time during Makefile processing.
var (
	edition  string // Sysbox Edition: CE or EE
	version  string // extracted from VERSION file
	commitId string // latest sysbox-mgr's git commit-id
	builtAt  string // build time
	builtBy  string // build owner
)

func main() {
	app := cli.NewApp()
	app.Name = "sysbox-mgr"
	app.Usage = usage
	app.Version = version

	var v []string
	if version != "" {
		v = append(v, version)
	}
	app.Version = strings.Join(v, "\n")

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "log, l",
			Value: "",
			Usage: "log file path or empty string for stderr output (default: \"\")",
		},
		cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "log categories to include (debug, info, warning, error, fatal)",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "log format; must be json or text (default = text)",
		},
		cli.BoolTFlag{
			Name:  "alias-dns",
			Usage: "aliases the DNS IP inside the system container to ensure it never has a localhost address; required for system containers on user-defined Docker bridge networks (default = true)",
		},
		cli.BoolFlag{
			Name:   "cpu-profiling",
			Usage:  "enable cpu-profiling data collection",
			Hidden: true,
		},
		cli.BoolFlag{
			Name:   "memory-profiling",
			Usage:  "enable memory-profiling data collection",
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "data-root",
			Value: "/var/lib/sysbox",
			Usage: "root directory for sysbox data store",
		},
		cli.BoolTFlag{
			Name:  "bind-mount-id-shift",
			Usage: "When set to true, Sysbox performs user and group ID shifting (e.g., shiftfs mounts) on host directories bind-mounted to the system containers so that they appear with correct ownership inside the container (default = true)",
		},
	}

	// show-version specialization.
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("sysbox-mgr\n"+
			"\tedition: \t%s\n"+
			"\tversion: \t%s\n"+
			"\tcommit: \t%s\n"+
			"\tbuilt at: \t%s\n"+
			"\tbuilt by: \t%s\n",
			edition, c.App.Version, commitId, builtAt, builtBy)
	}

	app.Before = func(ctx *cli.Context) error {
		if path := ctx.GlobalString("log"); path != "" {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
			if err != nil {
				return err
			}
			logrus.SetOutput(f)
		} else {
			logrus.SetOutput(os.Stderr)
		}

		if logFormat := ctx.GlobalString("log-format"); logFormat == "json" {
			logrus.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: "2006-01-02 15:04:05",
			})
		} else {
			logrus.SetFormatter(&logrus.TextFormatter{
				TimestampFormat: "2006-01-02 15:04:05",
				FullTimestamp:   true,
			})
		}

		// Set desired log-level.
		if logLevel := ctx.GlobalString("log-level"); logLevel != "" {
			switch logLevel {
			case "debug":
				logrus.SetLevel(logrus.DebugLevel)
			case "info":
				logrus.SetLevel(logrus.InfoLevel)
			case "warning":
				logrus.SetLevel(logrus.WarnLevel)
			case "error":
				logrus.SetLevel(logrus.ErrorLevel)
			case "fatal":
				logrus.SetLevel(logrus.FatalLevel)
			default:
				logrus.Fatalf("'%v' log-level option not recognized", logLevel)
			}
		} else {
			// Set 'info' as our default log-level.
			logrus.SetLevel(logrus.InfoLevel)
		}

		return nil
	}

	app.Action = func(ctx *cli.Context) error {

		logrus.Info("Starting ...")

		// If requested, launch cpu/mem profiling data collection.
		profile, err := runProfiler(ctx)
		if err != nil {
			return err
		}

		mgr, err := newSysboxMgr(ctx)
		if err != nil {
			return fmt.Errorf("failed to create sysbox-mgr: %v", err)
		}

		var signalChan = make(chan os.Signal, 1)
		signal.Notify(
			signalChan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT)
		go signalHandler(signalChan, mgr, profile)

		logrus.Infof("Listening on %v", mgr.grpcServer.GetAddr())
		if err := mgr.Start(); err != nil {
			return fmt.Errorf("failed to start sysbox-mgr: %v", err)
		}

		mgr.Stop()
		logrus.Info("Done.")
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}

// Run cpu / memory profiling collection.
func runProfiler(ctx *cli.Context) (interface{ Stop() }, error) {

	var prof interface{ Stop() }

	cpuProfOn := ctx.Bool("cpu-profiling")
	memProfOn := ctx.Bool("memory-profiling")

	// Cpu and Memory profiling options seem to be mutually exclused in pprof.
	if cpuProfOn && memProfOn {
		return nil, fmt.Errorf("Unsupported parameter combination: cpu and memory profiling")
	}

	// Typical / non-profiling case.
	if !(cpuProfOn || memProfOn) {
		return nil, nil
	}

	// Notice that 'NoShutdownHook' option is passed to profiler constructor to
	// avoid this one reacting to 'sigterm' signal arrival. IOW, we want
	// sysbox-mgr signal handler to be the one stopping all profiling tasks.

	if cpuProfOn {
		prof = profile.Start(
			profile.CPUProfile,
			profile.ProfilePath("."),
			profile.NoShutdownHook,
		)
		logrus.Info("Initiated cpu-profiling data collection.")
	}

	if memProfOn {
		prof = profile.Start(
			profile.MemProfile,
			profile.ProfilePath("."),
			profile.NoShutdownHook,
		)
		logrus.Info("Initiated memory-profiling data collection.")
	}

	return prof, nil
}

// sysbox-mgr signal handler goroutine.
func signalHandler(
	signalChan chan os.Signal,
	mgr *SysboxMgr,
	profile interface{ Stop() }) {

	s := <-signalChan

	logrus.Infof("Caught OS signal: %s", s)

	if err := mgr.Stop(); err != nil {
		logrus.Warnf("Failed to terminate sysbox-mgr gracefully: %s", err)
	}

	// Stop cpu/mem profiling tasks.
	if profile != nil {
		profile.Stop()
	}

	logrus.Info("Exiting.")
	os.Exit(0)
}
