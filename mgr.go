package main

import (
	"fmt"

	grpc "github.com/nestybox/sysvisor/sysvisor-ipc/sysvisorMgrGrpc"
	pb "github.com/nestybox/sysvisor/sysvisor-ipc/sysvisorMgrGrpc/protobuf"
	intf "github.com/nestybox/sysvisor/sysvisor-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

const (
	sysvisorRunDir = "/run/sysvisor"
	sysvisorLibDir = "/var/lib/sysvisor"
)

type SysvisorMgr struct {
	grpcServer *grpc.ServerStub
	subidAlloc intf.SubidAlloc
	dsVolMgr   intf.VolMgr
}

// newSysvisorMgr creates an instance of the sysvisor manager
func newSysvisorMgr(ctx *cli.Context) (*SysvisorMgr, error) {
	err := setupWorkDirs()
	if err != nil {
		return nil, fmt.Errorf("failed to setup the work dir: %v", err)
	}

	subidAlloc, err := setupSubidAlloc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup subid allocator: %v", err)
	}

	dsVolMgr, err := setupDsVolMgr(ctx)
	if err != nil {
		return nil, err
	}

	mgr := &SysvisorMgr{}

	cb := &grpc.ServerCallbacks{
		SubidAlloc:   subidAlloc.Alloc,
		SubidFree:    subidAlloc.Free,
		ReqSupMounts: mgr.reqSupMounts,
		RelSupMounts: mgr.relSupMounts,
	}

	mgr.grpcServer = grpc.NewServerStub(cb)
	mgr.subidAlloc = subidAlloc
	mgr.dsVolMgr = dsVolMgr

	return mgr, nil
}

// Start causes the sysvisor mgr to listen for connections
func (mgr *SysvisorMgr) Start() error {
	return mgr.grpcServer.Init()
}

// Cleanup performs cleanup actions
func (mgr *SysvisorMgr) Cleanup() error {
	return cleanupWorkDirs()
}

func (mgr *SysvisorMgr) reqSupMounts(id string, rootfs string, uid, gid uint32, shiftUids bool) ([]*pb.Mount, error) {
	supMounts := []specs.Mount{}

	m, err := mgr.dsVolMgr.CreateVol(id, rootfs, "/var/lib/docker", uid, gid, shiftUids)
	if err != nil {
		return []*pb.Mount{}, err
	}
	supMounts = append(supMounts, m...)

	// convert []spec.Mount to []*pb.Mount
	protoMounts := []*pb.Mount{}
	for _, sm := range supMounts {
		protoMount := &pb.Mount{
			Source: sm.Source,
			Dest:   sm.Destination,
			Type:   sm.Type,
			Opt:    sm.Options,
		}
		protoMounts = append(protoMounts, protoMount)
	}

	return protoMounts, nil
}

func (mgr *SysvisorMgr) relSupMounts(id string) error {
	err := mgr.dsVolMgr.DestroyVol(id)
	if err != nil {
		return fmt.Errorf("failed to release docker store mount: %v", err)
	}

	return nil
}
