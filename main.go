//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// Default subid range required by sysbox (allows 4k sys containers, each with 64k uid(gids))
var subidRangeSize uint64 = 268435456

const (
	usage = `sysbox manager

sysbox-mgr is the Sysbox manager daemon. It's main job is to provide services to other
sysbox components (e.g., sysbox-runc).`
)

// Globals to be populated at build time during Makefile processing.
var (
	version  string // extracted from VERSION file
	commitId string // latest git commit-id of sysbox superproject
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
			Value: "/dev/stdout",
			Usage: "log file path",
		},
		cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "log categories to include (debug, info, warning, error, fatal)",
		},
		cli.StringFlag{
			Name:  "subid-policy, p",
			Value: "reuse",
			Usage: "subid allocator exhaust policy ('reuse' or 'no-reuse')",
		},
		cli.Uint64Flag{
			Name:  "subid-range-size, r",
			Value: subidRangeSize,
			Usage: "subid allocator range (must be a multiple of 64K and <= 4G)",
		},
		cli.BoolFlag{
			Name:  "no-inner-docker-image-sharing",
			Usage: "Disable copy-on-write sharing of inner docker images between system containers; may increase container startup time and storage overhead",
		},
	}

	// show-version specialization.
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("sysbox-mgr\n"+
			"\tversion: \t%s\n"+
			"\tcommit: \t%s\n"+
			"\tbuilt at: \t%s\n"+
			"\tbuilt by: \t%s\n",
			c.App.Version, commitId, builtAt, builtBy)
	}

	app.Before = func(ctx *cli.Context) error {
		if path := ctx.GlobalString("log"); path != "" {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
			if err != nil {
				return err
			}

			// Set a proper logging formatter.
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors:     true,
				TimestampFormat: "2006-01-02 15:04:05",
				FullTimestamp:   true,
			})
			logrus.SetOutput(f)
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

		if ctx.GlobalUint64("subid-range-size") != 0 {
			subidRangeSize = ctx.GlobalUint64("subid-range-size")
		}

		if subidRangeSize%(1<<16) != 0 {
			return fmt.Errorf("invalid subid-range-size %d; must be a multiple of 64K", subidRangeSize)
		}

		if subidRangeSize > (1 << 32) {
			return fmt.Errorf("invalid subid-range-size %d; must be <= 4G", subidRangeSize)
		}

		return nil
	}

	app.Action = func(ctx *cli.Context) error {

		logrus.Info("Starting ...")

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
		go signalHandler(signalChan, mgr)

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

// sysbox-mgr signal handler goroutine.
func signalHandler(signalChan chan os.Signal, mgr *SysboxMgr) {

	s := <-signalChan

	logrus.Infof("Caught OS signal: %s", s)

	if err := mgr.Stop(); err != nil {
		logrus.Warnf("Failed to terminate sysbox-mgr gracefully: %s", err)
	}

	logrus.Info("Exiting.")
	os.Exit(0)
}
