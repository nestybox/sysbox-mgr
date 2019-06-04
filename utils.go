package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/nestybox/sysvisor-mgr/dsVolMgr"
	intf "github.com/nestybox/sysvisor-mgr/intf"
	"github.com/nestybox/sysvisor-mgr/subidAlloc"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func setupSubidAlloc(ctx *cli.Context) (intf.SubidAlloc, error) {
	var reusePol subidAlloc.ReusePolicy

	subuidSrc, err := os.Open("/etc/subuid")
	if err != nil {
		return nil, err
	}
	defer subuidSrc.Close()

	subgidSrc, err := os.Open("/etc/subgid")
	if err != nil {
		return nil, err
	}
	defer subgidSrc.Close()

	if ctx.GlobalString("subid-policy") == "no-reuse" {
		reusePol = subidAlloc.NoReuse
		logrus.Infof("Subid allocation exhaust policy set to \"no-reuse\"")
	} else {
		reusePol = subidAlloc.Reuse
		logrus.Infof("Subid allocation exhaust policy set to \"reuse\"")
	}

	subidAlloc, err := subidAlloc.New("sysvisor", reusePol, subuidSrc, subgidSrc)
	if err != nil {
		return nil, fmt.Errorf("failed to create the subid allocator: %v", err)
	}

	return subidAlloc, nil
}

func setupDsVolMgr(ctx *cli.Context) (intf.VolMgr, error) {
	hostDir := filepath.Join(sysvisorLibDir, "docker")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %v: %v", hostDir, err)
	}
	ds, err := dsVolMgr.New(hostDir)
	if err != nil {
		return nil, fmt.Errorf("failed to setup docker volume manager: %v", err)
	}
	return ds, nil
}

func setupWorkDirs() error {
	if err := cleanupWorkDirs(); err != nil {
		return err
	}
	if err := os.MkdirAll(sysvisorRunDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(sysvisorLibDir, 0700); err != nil {
		return err
	}
	return nil
}

func cleanupWorkDirs() error {

	if _, err := os.Stat(sysvisorRunDir); err == nil {
		if err := removeDirContents(sysvisorRunDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if _, err := os.Stat(sysvisorLibDir); err == nil {
		if err := removeDirContents(sysvisorLibDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return nil
}

func removeDirContents(path string) error {
	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return fmt.Errorf("ReadDir(%v) failed: %v", path, err)
	}
	for _, d := range dir {
		if err := os.RemoveAll(filepath.Join(path, d.Name())); err != nil {
			return fmt.Errorf("RemoveAll(%v) failed: %v", filepath.Join(path, d.Name()), err)
		}
	}
	return nil
}
