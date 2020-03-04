//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	grpc "github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
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
	restarted
)

type uidInfo struct {
	uid  uint32
	gid  uint32
	size uint64
}

type mntPrepRevInfo struct {
	path    string
	chown   bool
	origUid uint32
	origGid uint32
}

type containerInfo struct {
	state        containerState
	rootfs       string
	mntPrepRev   []mntPrepRevInfo
	mounts       []specs.Mount
	uidInfo      uidInfo
	shiftfsMarks []configs.ShiftfsMount
}

type SysboxMgr struct {
	grpcServer    *grpc.ServerStub
	subidAlloc    intf.SubidAlloc
	dsVolMgr      intf.VolMgr
	ksVolMgr      intf.VolMgr
	shiftfsMgr    intf.ShiftfsMgr
	contTable     map[string]containerInfo // cont id -> cont info
	ctLock        sync.Mutex
	rootfsTable   map[string]string // cont rootfs -> cont id; used by rootfs monitor
	rtLock        sync.Mutex
	rootfsMonStop chan int
	rootfsWatcher *fsnotify.Watcher
	mntPrepTable  map[string]string // mount source -> cont id
	mntPrepLock   sync.Mutex
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

	ksVolMgr, err := setupKsVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup kubelet-store vol mgr: %v", err)
	}

	shiftfsMgr, err := shiftfsMgr.New()
	if err != nil {
		return nil, fmt.Errorf("failed to setup shiftfs mgr: %v", err)
	}

	mgr := &SysboxMgr{
		subidAlloc:    subidAlloc,
		dsVolMgr:      dsVolMgr,
		ksVolMgr:      ksVolMgr,
		shiftfsMgr:    shiftfsMgr,
		contTable:     make(map[string]containerInfo),
		rootfsTable:   make(map[string]string),
		rootfsMonStop: make(chan int),
		mntPrepTable:  make(map[string]string),
	}

	cb := &grpc.ServerCallbacks{
		Register:       mgr.register,
		Unregister:     mgr.unregister,
		SubidAlloc:     mgr.allocSubid,
		ReqMounts:      mgr.reqMounts,
		PrepMounts:     mgr.prepMounts,
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
			state:        started,
			mntPrepRev:   []mntPrepRevInfo{},
			shiftfsMarks: []configs.ShiftfsMount{},
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
	info.state = restarted
	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	// remove the rootfs watch
	if info.rootfs != "" {
		rootfs := sanitizeRootfs(id, info.rootfs)
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
	var err error

	// update container state
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("can't unregister container %s; not found in container table", id)
	}
	if info.state == stopped {
		return fmt.Errorf("redundant container unregistration for container %s", id)
	}
	info.state = stopped

	if len(info.shiftfsMarks) != 0 {
		if err = mgr.shiftfsMgr.Unmark(id, info.shiftfsMarks); err != nil {
			return fmt.Errorf("failed to remove shiftfs marks for container %s: %s", id, err)
		}
		info.shiftfsMarks = []configs.ShiftfsMount{}
	}

	// revert mount prep actions
	mgr.mntPrepLock.Lock()
	for _, revInfo := range info.mntPrepRev {
		if revInfo.chown {
			if err = rChown(revInfo.path, revInfo.origUid, revInfo.origGid); err != nil {
				mgr.mntPrepLock.Unlock()
				return fmt.Errorf("failed to revert ownership of mount source at %s: %s", revInfo.path, err)
			}
		}
		delete(mgr.mntPrepTable, revInfo.path)
	}
	mgr.mntPrepLock.Unlock()

	// Request the volume managers to sync back their contents to the container's rootfs.
	//
	// Note that we do this when the container is stopped, not when it's running. This
	// means we take the performance hit on container stop. The performance hit is a
	// function of how many changes the sys container did on the directory where the
	// volume is mounted.  If in the future we think the hit is too much, we could do
	// the sync periodically while the container is running (e.g., using a combination
	// of fsnotify + rsync).
	for _, mnt := range info.mounts {
		switch mnt.Destination {
		case "/var/lib/docker":
			err = mgr.dsVolMgr.SyncOut(id)
		case "/var/lib/kubelet":
			err = mgr.ksVolMgr.SyncOut(id)
		}
		if err != nil {
			return fmt.Errorf("sync-out for volume backing %s for container %s failed: %v", mnt.Destination, id, err)
		}
	}

	mgr.ctLock.Lock()
	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	// setup rootfs watch (allows us to get notified when the container's rootfs is
	// removed)
	if info.rootfs != "" {
		rootfs := sanitizeRootfs(id, info.rootfs)
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

	for _, mnt := range info.mounts {
		var err error

		switch mnt.Destination {
		case "/var/lib/docker":
			err = mgr.dsVolMgr.DestroyVol(id)
		case "/var/lib/kubelet":
			err = mgr.ksVolMgr.DestroyVol(id)
		}
		if err != nil {
			logrus.Errorf("rootfsMon: failed to destroy volume backing %s for container %s: %s", mnt.Destination, id, err)
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

func (mgr *SysboxMgr) reqMounts(id, rootfs string, uid, gid uint32, shiftUids bool, reqList []ipcLib.MountReqInfo) ([]specs.Mount, error) {

	if len(reqList) == 0 {
		return nil, fmt.Errorf("request list is empty!")
	}

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return nil, fmt.Errorf("container %s is not registered", id)
	}

	// if this is a stopped container that is being re-started, no need to setup mounts
	// (stopped containers keep their existing mounts until removed)
	if info.state == restarted {
		return info.mounts, nil
	}

	// call appropriate handlers
	mounts := []specs.Mount{}
	for _, req := range reqList {

		var err error
		m := []specs.Mount{}

		switch req.Dest {
		case "/var/lib/docker":
			m, err = mgr.dsVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, shiftUids, 0700)
		case "/var/lib/kubelet":
			m, err = mgr.ksVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, shiftUids, 0755)
		default:
			err = fmt.Errorf("unknown mount request type")
		}
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, m...)
	}

	if len(mounts) > 0 {
		info.rootfs = rootfs
		info.mounts = mounts
		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return mounts, nil
}

func (mgr *SysboxMgr) prepMounts(id string, uid, gid uint32, shiftUids bool, prepList []ipcLib.MountPrepInfo) error {
	var origUid, origGid uint32

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("container %s is not registered", id)
	}

	for _, prepInfo := range prepList {
		src := prepInfo.Source

		// if the mount is exclusive and another sys container has the same mount source, return error
		mgr.mntPrepLock.Lock()
		cid, found := mgr.mntPrepTable[src]
		if found && prepInfo.Exclusive {
			mgr.mntPrepLock.Unlock()
			return fmt.Errorf("mount prep failed; source at %s is already in use by container %s", src, cid)
		}
		mgr.mntPrepTable[src] = id
		mgr.mntPrepLock.Unlock()

		// if uid shifting is enabled, modify the ownership of the mount source to uid:gid
		if shiftUids {

			// get the current uid(gid) for the mount source
			fi, err := os.Stat(src)
			if err != nil {
				mgr.mntPrepLock.Lock()
				delete(mgr.mntPrepTable, src)
				mgr.mntPrepLock.Unlock()
				return fmt.Errorf("failed to stat mount source at %s", src)
			}

			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				mgr.mntPrepLock.Lock()
				delete(mgr.mntPrepTable, src)
				mgr.mntPrepLock.Unlock()
				return fmt.Errorf("failed to convert to syscall.Stat_t")
			}

			origUid = st.Uid
			origGid = st.Gid

			if err := rChown(src, uid, gid); err != nil {
				mgr.mntPrepLock.Lock()
				delete(mgr.mntPrepTable, src)
				mgr.mntPrepLock.Unlock()
				return fmt.Errorf("failed to chown mount source at %s: %s", src, err)
			}
		}

		// store the prep info so we can revert it when the container is stopped
		revInfo := mntPrepRevInfo{
			path:    src,
			chown:   shiftUids,
			origUid: origUid,
			origGid: origGid,
		}
		info.mntPrepRev = append(info.mntPrepRev, revInfo)

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return nil
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
		uid, gid, err := mgr.subidAlloc.Alloc(id, size, "")
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
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("can't pause container %s; not found in container table", id)
	}

	// Request all volume managers to sync back contents to the container's rootfs
	for _, mnt := range info.mounts {
		var err error

		switch mnt.Destination {
		case "/var/lib/docker":
			err = mgr.dsVolMgr.SyncOut(id)
		case "/var/lib/kubelet":
			err = mgr.ksVolMgr.SyncOut(id)
		}
		if err != nil {
			return fmt.Errorf("sync-out for volume backing %s for container %s failed: %v", mnt.Destination, id, err)
		}
	}

	return nil
}
