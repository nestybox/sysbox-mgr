package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// TODO: version shold populated by the Makefile as set in the sysvisor VERSION file; see
// runc Makefile for an example.
var version = "TBD"

// subid range required by sysvisor (4k sys containers, each with 64k uid(gids))
var subidRange uint64 = 268435456

const (
	usage = `sysvisor manager

sysvisor-mgr is a daemon that provides services to other sysvisor
components (e.g., sysvisor-runc).`
)

func main() {
	app := cli.NewApp()
	app.Name = "sysvisor-mgr"
	app.Usage = usage

	var v []string
	if version != "" {
		v = append(v, version)
	}
	app.Version = strings.Join(v, "\n")

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "enable debug output in logs",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "/dev/stdout",
			Usage: "log file path",
		},
		cli.StringFlag{
			Name:  "subid-policy",
			Value: "reuse",
			Usage: "subid exhaust policy ('reuse' or 'no-reuse')",
		},
		cli.Uint64Flag{
			Name:  "subid-range",
			Value: subidRange,
			Usage: "subid range size (must be a multiple of 64k (each sys container uses 64K uids & gids); must not exceed 4GB)",
		},
	}

	app.Before = func(ctx *cli.Context) error {
		if ctx.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		if path := ctx.GlobalString("log"); path != "" {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
			if err != nil {
				return err
			}

			// Set a proper logging formatter.
			logrus.SetFormatter(&logrus.TextFormatter{
				ForceColors: true,
				TimestampFormat : "2006-01-02 15:04:05",
				FullTimestamp: true,
			})
			logrus.SetOutput(f)
		}
		subidRange = ctx.GlobalUint64("subid-range")
		if subidRange < (1 << 16) {
			return fmt.Errorf("invalid subid-range %d; must be >= 64K", subidRange)
		}
		if subidRange > (1 << 32) {
			return fmt.Errorf("invalid subid-range %d; must be <= 4G", subidRange)
		}
		return nil
	}

	app.Action = func(ctx *cli.Context) error {
		logrus.Info("Starting ...")
		mgr, err := newSysvisorMgr(ctx)
		if err != nil {
			return fmt.Errorf("failed to create sysvisor mgr: %v", err)
		}
		logrus.Infof("Listening on %v", mgr.grpcServer.GetAddr())
		if err := mgr.Start(); err != nil {
			return fmt.Errorf("failed to start sysvisor mgr: %v", err)
		}
		mgr.Cleanup()
		logrus.Info("Done.")
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
