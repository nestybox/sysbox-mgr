package main

import (
	"fmt"
	"os"

	"github.com/nestybox/sysvisor/sysvisor-mgr/idAlloc"
	grpc "github.com/nestybox/sysvisor/sysvisor-protobuf/sysvisorMgrGrpc"
)

type SysvisorMgr struct {
	grpcServer *grpc.ServerStub
}

// newSysvisorMgr creates an instance of the sysvisor manager
func newSysvisorMgr() (*SysvisorMgr, error) {

	subuid, err := os.Open("/etc/subuid")
	if err != nil {
		return nil, err
	}
	defer subuid.Close()

	uidAllocator, err := idAlloc.New("sysvisor", idAlloc.Reuse, subuid)
	if err != nil {
		return nil, fmt.Errorf("failed to create a uid allocator: %v", err)
	}

	cb := &grpc.ServerCallbacks{
		UidAlloc: uidAllocator.Alloc,
		UidFree:  uidAllocator.Free,
	}

	return &SysvisorMgr{
		grpcServer: grpc.NewServerStub(cb),
	}, nil
}

// Start causes the sysvisor mgr to listen for connections
func (mgr *SysvisorMgr) Start() error {
	return mgr.grpcServer.Init()
}
