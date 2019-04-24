package main

import (
	"fmt"
	"os"

	intf "github.com/nestybox/sysvisor/sysvisor-mgr/intf"
	"github.com/nestybox/sysvisor/sysvisor-mgr/subidAlloc"
	grpc "github.com/nestybox/sysvisor/sysvisor-protobuf/sysvisorMgrGrpc"
)

type SysvisorMgr struct {
	grpcServer *grpc.ServerStub
	subidAlloc intf.SubidAlloc
}

func setupSubidAlloc() (intf.SubidAlloc, error) {

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

	// set alloc policy to re-use (i.e., if we run out of subuid(gid), reuse allocated ones)
	subidAlloc, err := subidAlloc.New("sysvisor", subidAlloc.Reuse, subuidSrc, subgidSrc)
	if err != nil {
		return nil, fmt.Errorf("failed to create the subid allocator: %v", err)
	}

	return subidAlloc, nil
}

// newSysvisorMgr creates an instance of the sysvisor manager
func newSysvisorMgr() (*SysvisorMgr, error) {

	subidAlloc, err := setupSubidAlloc()
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
