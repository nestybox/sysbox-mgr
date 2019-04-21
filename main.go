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

const (
	usage = `sysvisor manager

sysvisor-mgr is a daemon that provides services to other sysvisor
components (e.g., sysvisor-runc).

   # sysvisor-mgr
`
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
			Value: "/dev/null",
			Usage: "log file path",
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
			logrus.SetOutput(f)
		}
		return nil
	}

	app.Action = func(ctx *cli.Context) error {
		mgr, err := newSysvisorMgr()
		if err != nil {
			return fmt.Errorf("failed to create sysvisor mgr: %v", err)
		}
		logrus.Debug("Starting ...")
		if err := mgr.Start(); err != nil {
			return fmt.Errorf("failed to start sysvisor mgr: %v", err)
		}
		logrus.Debug("Done.")
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
