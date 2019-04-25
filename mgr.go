package main

import (
	"fmt"
	"os"

	intf "github.com/nestybox/sysvisor/sysvisor-mgr/intf"
	"github.com/nestybox/sysvisor/sysvisor-mgr/subidAlloc"
	grpc "github.com/nestybox/sysvisor/sysvisor-protobuf/sysvisorMgrGrpc"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	sysvisorRunDir = "/run/sysvisor"
)

type SysvisorMgr struct {
	grpcServer *grpc.ServerStub
	subidAlloc intf.SubidAlloc
}

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

func cleanupRunDir() error {
	return os.RemoveAll(sysvisorRunDir)
}

func setupRunDir() error {
	if err := cleanupRunDir(); err != nil {
		return err
	}
	if err := os.MkdirAll(sysvisorRunDir, 0700); err != nil {
		return err
	}
	return nil
}

// newSysvisorMgr creates an instance of the sysvisor manager
func newSysvisorMgr(ctx *cli.Context) (*SysvisorMgr, error) {

	err := setupRunDir()
	if err != nil {
		return nil, fmt.Errorf("failed to setup the run dir: %v", err)
	}

	subidAlloc, err := setupSubidAlloc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup subid allocator: %v", err)
	}

	cb := &grpc.ServerCallbacks{
		SubidAlloc: subidAlloc.Alloc,
		SubidFree:  subidAlloc.Free,
	}

	mgr := &SysvisorMgr{
		subidAlloc: subidAlloc,
		grpcServer: grpc.NewServerStub(cb),
	}

	return mgr, nil
}

// Start causes the sysvisor mgr to listen for connections
func (mgr *SysvisorMgr) Start() error {
	return mgr.grpcServer.Init()
}

// Cleanup performs cleanup actions
func (mgr *SysvisorMgr) Cleanup() error {
	return cleanupRunDir()
}
