//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package main

import (
	"fmt"
	"sync"

	"github.com/fsnotify/fsnotify"
	grpc "github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	pb "github.com/nestybox/sysbox-ipc/sysboxMgrGrpc/protobuf"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/shiftfsMgr"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	sysboxRunDir = "/run/sysbox"
	sysboxLibDir = "/var/lib/sysbox"
)

type containerState int

const (
	started containerState = iota
	stopped
)

type uidInfo struct {
	uid  uint32
	gid  uint32
	size uint64
}

type containerInfo struct {
	state        containerState
	rootfs       string
	supMounts    []specs.Mount
	uidInfo      uidInfo
	shiftfsMarks []configs.ShiftfsMount
}

type SysboxMgr struct {
	grpcServer    *grpc.ServerStub
	subidAlloc    intf.SubidAlloc
	dsVolMgr      intf.VolMgr
	shiftfsMgr    intf.ShiftfsMgr
	contTable     map[string]containerInfo // cont id -> cont info
	ctLock        sync.Mutex
	rootfsTable   map[string]string // cont rootfs -> cont id; used by rootfs monitor
	rtLock        sync.Mutex
	rootfsMonStop chan int
	rootfsWatcher *fsnotify.Watcher
}

// newSysboxMgr creates an instance of the sysbox manager
func newSysboxMgr(ctx *cli.Context) (*SysboxMgr, error) {
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
		return nil, fmt.Errorf("failed to setup docker-store vol mgr: %v", err)
	}

	shiftfsMgr, err := shiftfsMgr.New()
	if err != nil {
		return nil, fmt.Errorf("failed to setup shiftfs mgr: %v", err)
	}

	mgr := &SysboxMgr{
		subidAlloc:    subidAlloc,
		dsVolMgr:      dsVolMgr,
		shiftfsMgr:    shiftfsMgr,
		contTable:     make(map[string]containerInfo),
		rootfsTable:   make(map[string]string),
		rootfsMonStop: make(chan int),
	}

	cb := &grpc.ServerCallbacks{
		Register:       mgr.register,
		Unregister:     mgr.unregister,
		SubidAlloc:     mgr.allocSubid,
		ReqSupMounts:   mgr.reqSupMounts,
		ReqShiftfsMark: mgr.reqShiftfsMark,
		Pause:          mgr.pause,
	}

	mgr.grpcServer = grpc.NewServerStub(cb)

	return mgr, nil
}

func (mgr *SysboxMgr) Start() error {

	// setup rootfs watcher (to detect container removal)
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to setup fsnotify watcher: %v", err)
	}
	mgr.rootfsWatcher = w

	// start the the rootfs monitor (listens for rootfs watch events)
	go mgr.rootfsMon()

	// listen for grpc connections
	return mgr.grpcServer.Init()
}

func (mgr *SysboxMgr) Cleanup() error {
	mgr.rootfsMonStop <- 1

	if err := mgr.rootfsWatcher.Close(); err != nil {
		return fmt.Errorf("failed to close rootfs rm fs watcher: %v", err)
	}

	if err := cleanupWorkDirs(); err != nil {
		return fmt.Errorf("failed to cleanup work dirs: %v", err)
	}

	return nil
}

// Registers a container with sysbox-mgr
func (mgr *SysboxMgr) register(id string) error {

	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	if !found {
		// new container
		info = containerInfo{
			state: started,
		}
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
		logrus.Infof("registered new container %s", id)
		return nil
	}

	// re-started container
	if info.state != stopped {
		mgr.ctLock.Unlock()
		return fmt.Errorf("redundant container registration for container %s", id)
	}
	info.state = started
	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	// remove the rootfs watch
	if info.rootfs != "" {
		rootfs := sanitizeRootfs(info.rootfs)
		mgr.rootfsWatcher.Remove(rootfs)
		mgr.rtLock.Lock()
		delete(mgr.rootfsTable, rootfs)
		mgr.rtLock.Unlock()
		logrus.Debugf("removed fs watch on %s", rootfs)
	}

	logrus.Infof("registered container %s", id)
	return nil
}

// Unregisters a container with sysbox-mgr
func (mgr *SysboxMgr) unregister(id string) error {

	// update container state
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("can't unregister container %s; not found in container table", id)
	}
	if info.state != started {
		return fmt.Errorf("redundant container unregistration for container %s", id)
	}
	info.state = stopped

	// Request shiftfs manager to remove shiftfs mounts
	if len(info.shiftfsMarks) != 0 {
		if err := mgr.shiftfsMgr.Unmark(id, info.shiftfsMarks); err != nil {
			return fmt.Errorf("failed to remove shiftfs marks for container %s: %s", id, err)
		}
		info.shiftfsMarks = []configs.ShiftfsMount{}
	}

	// Request docker-store volume manager to sync back contents to the container's rootfs
	if err := mgr.dsVolMgr.SyncOut(id); err != nil {
		return fmt.Errorf("docker-store vol sync-out failed: %v", err)
	}

	mgr.ctLock.Lock()
	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	// setup rootfs watch (allows us to get notified when the container's rootfs is
	// removed)
	if info.rootfs != "" {
		rootfs := sanitizeRootfs(info.rootfs)
		mgr.rtLock.Lock()
		mgr.rootfsTable[rootfs] = id
		mgr.rtLock.Unlock()
		mgr.rootfsWatcher.Add(rootfs)

		logrus.Debugf("added fs watch on %s", rootfs)
	}

	logrus.Infof("unregistered container %s", id)
	return nil
}

// rootfs monitor thread: checks for rootfs removal event and removes container.
func (mgr *SysboxMgr) rootfsMon() {
	logrus.Debugf("rootfsMon starting ...")

	for {
		select {
		case event := <-mgr.rootfsWatcher.Events:
			if event.Op&fsnotify.Remove == fsnotify.Remove {
				rootfs := event.Name
				mgr.rtLock.Lock()
				id, found := mgr.rootfsTable[rootfs]
				if !found {
					// event is for a file or sub-dir of a container's rootfs, not for the rootfs itself; ignore it
					mgr.rtLock.Unlock()
					break
				}
				logrus.Debugf("roofsMon: rm on %s", rootfs)
				delete(mgr.rootfsTable, rootfs)
				mgr.rtLock.Unlock()
				mgr.rootfsWatcher.Remove(rootfs)
				mgr.removeCont(id)
			}

		case err := <-mgr.rootfsWatcher.Errors:
			logrus.Errorf("roofsMon: rootfs watch error: %v", err)

		case <-mgr.rootfsMonStop:
			logrus.Debugf("rootfsMon exiting ...")
			return
		}
	}
}

// removes all resources associated with a container
func (mgr *SysboxMgr) removeCont(id string) {

	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		logrus.Errorf("can't remove container %s; info not found in table", id)
		return
	}

	if len(info.supMounts) != 0 {
		if err := mgr.dsVolMgr.DestroyVol(id); err != nil {
			logrus.Errorf("rootfsMon: failed to destroy docker-store-volume for container %s: %s", id, err)
		}
	}

	if info.uidInfo.size != 0 {
		if err := mgr.subidAlloc.Free(id); err != nil {
			logrus.Errorf("rootfsMon: failed to free uid(gid) for container %s: %s", id, err)
		}
	}

	mgr.ctLock.Lock()
	delete(mgr.contTable, id)
	mgr.ctLock.Unlock()

	logrus.Infof("released resources for container %s", id)
}

func (mgr *SysboxMgr) reqSupMounts(id string, rootfs string, uid, gid uint32, shiftUids bool) ([]*pb.Mount, error) {

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return []*pb.Mount{}, fmt.Errorf("container %s is not registered", id)
	}

	// if this is a newly started container, setup its supplementary mounts
	// (started or stopped containers keep their supp mounts until removed)
	if len(info.supMounts) == 0 {
		info.rootfs = rootfs
		info.supMounts = []specs.Mount{}

		// docker-store-volume mount
		m, err := mgr.dsVolMgr.CreateVol(id, rootfs, "/var/lib/docker", uid, gid, shiftUids)
		if err != nil {
			return []*pb.Mount{}, err
		}
		info.supMounts = append(info.supMounts, m...)

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	// TODO: this conversion should be moved to the GRPC server side ...
	// convert []spec.Mount to []*pb.Mount
	protoMounts := []*pb.Mount{}
	for _, sm := range info.supMounts {
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

func (mgr *SysboxMgr) allocSubid(id string, size uint64) (uint32, uint32, error) {

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return 0, 0, fmt.Errorf("container %s is not registered", id)
	}

	// if this is a newly started container, allocate the uid/gid range
	// (started or stopped containers keep their uid/gid range until removed)
	if info.uidInfo.size == 0 {
		uid, gid, err := mgr.subidAlloc.Alloc(id, size)
		if err != nil {
			return uid, gid, fmt.Errorf("failed to allocate uid(gid) for %s: %s", id, err)
		}
		info.uidInfo = uidInfo{
			uid:  uid,
			gid:  gid,
			size: size,
		}
		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return info.uidInfo.uid, info.uidInfo.gid, nil
}

func (mgr *SysboxMgr) reqShiftfsMark(id string, rootfs string, mounts []configs.ShiftfsMount) error {

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("container %s is not registered", id)
	}

	if len(info.shiftfsMarks) == 0 {
		info.shiftfsMarks = []configs.ShiftfsMount{}

		rootfsMnt := configs.ShiftfsMount{
			Source:   rootfs,
			Readonly: false,
		}
		allMounts := append(mounts, rootfsMnt)

		if err := mgr.shiftfsMgr.Mark(id, allMounts); err != nil {
			return err
		}

		info.shiftfsMarks = allMounts

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return nil
}

func (mgr *SysboxMgr) pause(id string) error {

	mgr.ctLock.Lock()
	_, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("can't pause container %s; not found in container table", id)
	}

	// Request docker-store volume manager to sync back contents to the container's rootfs
	if err := mgr.dsVolMgr.SyncOut(id); err != nil {
		return fmt.Errorf("docker-store vol sync-out failed: %v", err)
	}

	return nil
}
