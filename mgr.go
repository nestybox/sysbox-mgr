//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	grpc "github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	"github.com/nestybox/sysbox-libs/dockerUtils"
	"github.com/nestybox/sysbox-libs/formatter"
	libutils "github.com/nestybox/sysbox-libs/utils"
	utils "github.com/nestybox/sysbox-libs/utils"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/shiftfsMgr"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	sysboxRunDir        = "/run/sysbox"
	sysboxLibDirDefault = "/var/lib/sysbox"
)

var sysboxLibDir string

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

type mountInfo struct {
	kind   ipcLib.MntKind
	mounts []specs.Mount
}

type containerInfo struct {
	state        containerState
	rootfs       string
	mntPrepRev   []mntPrepRevInfo
	mounts       []mountInfo
	uidInfo      uidInfo
	shiftfsMarks []configs.ShiftfsMount
	autoRemove   bool
}

type SysboxMgr struct {
	mgrCfg            *ipcLib.MgrConfig
	grpcServer        *grpc.ServerStub
	subidAlloc        intf.SubidAlloc
	dockerVolMgr      intf.VolMgr
	kubeletVolMgr     intf.VolMgr
	containerdVolMgr  intf.VolMgr
	shiftfsMgr        intf.ShiftfsMgr
	hostDistro        string
	hostKernelHdrPath string
	linuxHeaderMounts []specs.Mount
	libModMounts      []specs.Mount
	contTable         map[string]containerInfo // cont id -> cont info
	ctLock            sync.Mutex
	rootfsTable       map[string]string // cont rootfs -> cont id; used by rootfs monitor
	rtLock            sync.Mutex
	rootfsMonStop     chan int
	rootfsWatcher     *fsnotify.Watcher
	exclMntTable      *exclusiveMntTable
}

// newSysboxMgr creates an instance of the sysbox manager
func newSysboxMgr(ctx *cli.Context) (*SysboxMgr, error) {
	var err error

	err = preFlightCheck()
	if err != nil {
		return nil, fmt.Errorf("preflight check failed: %s", err)
	}

	sysboxLibDir = ctx.GlobalString("data-root")
	if sysboxLibDir == "" {
		sysboxLibDir = sysboxLibDirDefault
	}
	logrus.Infof("Sysbox data root: %s", sysboxLibDir)

	err = setupWorkDirs()
	if err != nil {
		return nil, fmt.Errorf("failed to setup the sysbox work dirs: %v", err)
	}

	subidAlloc, err := setupSubidAlloc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup subid allocator: %v", err)
	}

	dockerVolMgr, err := setupDockerVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup docker vol mgr: %v", err)
	}

	kubeletVolMgr, err := setupKubeletVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup kubelet vol mgr: %v", err)
	}

	containerdVolMgr, err := setupContainerdVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup containerd vol mgr: %v", err)
	}

	shiftfsMgr, err := shiftfsMgr.New()
	if err != nil {
		return nil, fmt.Errorf("failed to setup shiftfs mgr: %v", err)
	}

	hostDistro, err := libutils.GetDistro()
	if err != nil {
		return nil, fmt.Errorf("failed to identify system's linux distribution: %v", err)
	}

	hostKernelHdrPath, err := libutils.GetLinuxHeaderPath(hostDistro)
	if err != nil {
		return nil, fmt.Errorf("failed to identify system's linux-header path: %v", err)
	}

	linuxHeaderMounts, err := getLinuxHeaderMounts(hostKernelHdrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute linux header mounts: %v", err)
	}

	libModMounts, err := getLibModMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to compute kernel-module mounts: %v", err)
	}

	mgrCfg := &ipcLib.MgrConfig{
		AliasDns: ctx.GlobalBoolT("alias-dns"),
	}

	if mgrCfg.AliasDns == true {
		logrus.Infof("Sys container DNS aliasing enabled.")
	} else {
		logrus.Infof("Sys container DNS aliasing disabled.")
	}

	mgr := &SysboxMgr{
		mgrCfg:            mgrCfg,
		subidAlloc:        subidAlloc,
		dockerVolMgr:      dockerVolMgr,
		kubeletVolMgr:     kubeletVolMgr,
		containerdVolMgr:  containerdVolMgr,
		shiftfsMgr:        shiftfsMgr,
		hostDistro:        hostDistro,
		hostKernelHdrPath: hostKernelHdrPath,
		linuxHeaderMounts: linuxHeaderMounts,
		libModMounts:      libModMounts,
		contTable:         make(map[string]containerInfo),
		rootfsTable:       make(map[string]string),
		rootfsMonStop:     make(chan int),
		exclMntTable:      newExclusiveMntTable(),
	}

	cb := &grpc.ServerCallbacks{
		Register:       mgr.register,
		Unregister:     mgr.unregister,
		SubidAlloc:     mgr.allocSubid,
		ReqMounts:      mgr.reqMounts,
		PrepMounts:     mgr.prepMounts,
		ReqShiftfsMark: mgr.reqShiftfsMark,
		ReqFsState:     mgr.reqFsState,
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

	// start the rootfs monitor (listens for rootfs watch events)
	go mgr.rootfsMon()

	logrus.Info("Ready ...")

	// listen for grpc connections
	return mgr.grpcServer.Init()
}

func (mgr *SysboxMgr) Stop() error {

	logrus.Info("Stopping (gracefully) ...")

	mgr.ctLock.Lock()
	if len(mgr.contTable) > 0 {
		logrus.Warn("The following containers are active and will stop operating properly:")
		for id := range mgr.contTable {
			logrus.Warnf("container id: %s", formatter.ContainerID{id})
		}
	}
	mgr.ctLock.Unlock()

	mgr.rootfsMonStop <- 1
	if err := mgr.rootfsWatcher.Close(); err != nil {
		logrus.Warnf("failed to close rootfs watcher: %v", err)
	}

	mgr.dockerVolMgr.SyncOutAndDestroyAll()
	mgr.kubeletVolMgr.SyncOutAndDestroyAll()
	mgr.containerdVolMgr.SyncOutAndDestroyAll()
	mgr.shiftfsMgr.UnmarkAll()

	if err := cleanupWorkDirs(); err != nil {
		logrus.Warnf("failed to cleanup work dirs: %v", err)
	}

	logrus.Info("Stopped.")

	return nil
}

// Registers a container with sysbox-mgr
func (mgr *SysboxMgr) register(id string) (*ipcLib.MgrConfig, error) {

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

		logrus.Infof("registered new container %s", formatter.ContainerID{id})
		return mgr.mgrCfg, nil
	}

	// re-started container
	if info.state != stopped {
		mgr.ctLock.Unlock()
		return nil, fmt.Errorf("redundant container registration for container %s",
			formatter.ContainerID{id})
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

	logrus.Infof("registered container %s", formatter.ContainerID{id})
	return mgr.mgrCfg, nil
}

// Unregisters a container with sysbox-mgr
func (mgr *SysboxMgr) unregister(id string) error {
	var err error

	// update container state
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("can't unregister container %s; not found in container table",
			formatter.ContainerID{id})
	}
	if info.state == stopped {
		return fmt.Errorf("redundant container unregistration for container %s",
			formatter.ContainerID{id})
	}
	info.state = stopped

	if len(info.shiftfsMarks) != 0 {
		if err = mgr.shiftfsMgr.Unmark(id, info.shiftfsMarks); err != nil {
			logrus.Warnf("failed to remove shiftfs marks for container %s: %s",
				formatter.ContainerID{id}, err)
		}
		info.shiftfsMarks = []configs.ShiftfsMount{}
	}

	// revert mount prep actions
	for _, revInfo := range info.mntPrepRev {
		if revInfo.chown {
			logrus.Infof("reverting chown on %s to %d:%d for %s", revInfo.path, revInfo.origUid,
				revInfo.origGid, formatter.ContainerID{id})

			if err = rChown(revInfo.path, revInfo.origUid, revInfo.origGid); err != nil {
				logrus.Warnf("failed to revert ownership of mount source at %s: %s", revInfo.path, err)
			}

			logrus.Infof("done reverting chown on %s for %s", revInfo.path,
				formatter.ContainerID{id})
		}

		mgr.exclMntTable.remove(revInfo.path, id)
	}

	mgr.ctLock.Lock()
	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	// Request the volume managers to copy their contents to the container's rootfs.
	if !info.autoRemove {
		if err := mgr.volSyncOut(id, info); err != nil {
			logrus.Warnf("sync-out for container %s failed: %v",
				formatter.ContainerID{id}, err)
		}
	}

	// setup rootfs watch (allows us to get notified when the container's rootfs is removed)
	if info.rootfs != "" {
		rootfs := sanitizeRootfs(id, info.rootfs)

		mgr.rtLock.Lock()
		mgr.rootfsTable[rootfs] = id
		mgr.rootfsWatcher.Add(rootfs)

		// It may be the case that rootfs has been deleted by the time we tell the
		// rootfsWatcher, which means the watcher won't catch the rootfs removal
		// event. In this case, let's cancel the watch event and remove the
		// sysbox-mgr state for the container.

		if _, err := os.Stat(rootfs); os.IsNotExist(err) {
			delete(mgr.rootfsTable, rootfs)
			mgr.rootfsWatcher.Remove(rootfs)
			mgr.rtLock.Unlock()
			mgr.removeCont(id)
			return nil
		}

		mgr.rtLock.Unlock()
		logrus.Debugf("added fs watch on %s", rootfs)
	}

	logrus.Infof("unregistered container %s", formatter.ContainerID{id})
	return nil
}

func (mgr *SysboxMgr) volSyncOut(id string, info containerInfo) error {
	var err error
	failedVols := []string{}

	for _, mnt := range info.mounts {
		switch mnt.kind {
		case ipcLib.MntVarLibDocker:
			err = mgr.dockerVolMgr.SyncOut(id)
		case ipcLib.MntVarLibKubelet:
			err = mgr.kubeletVolMgr.SyncOut(id)
		case ipcLib.MntVarLibContainerdOvfs:
			err = mgr.containerdVolMgr.SyncOut(id)
		}

		if err != nil {
			failedVols = append(failedVols, mnt.kind.String())
		}
	}

	if len(failedVols) > 0 {
		return fmt.Errorf("sync-out for volume backing %s failed: %v", failedVols, err)
	}

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
					// ignore the event: it's either for a file or sub-dir of a
					// container's rootfs, or for the rootfs itself but the event was
					// canceled (see unregister()).
					mgr.rtLock.Unlock()
					break
				}
				logrus.Debugf("rootfsMon: rm on %s", rootfs)
				delete(mgr.rootfsTable, rootfs)
				mgr.rtLock.Unlock()
				mgr.rootfsWatcher.Remove(rootfs)
				mgr.removeCont(id)
			}

		case err := <-mgr.rootfsWatcher.Errors:
			logrus.Errorf("rootfsMon: rootfs watch error: %v", err)

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
	if !found {
		mgr.ctLock.Unlock()
		return
	}
	delete(mgr.contTable, id)
	mgr.ctLock.Unlock()

	for _, mnt := range info.mounts {
		var err error

		switch mnt.kind {

		case ipcLib.MntVarLibDocker:
			err = mgr.dockerVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibKubelet:
			err = mgr.kubeletVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibContainerdOvfs:
			err = mgr.containerdVolMgr.DestroyVol(id)

		}
		if err != nil {
			logrus.Errorf("rootfsMon: failed to destroy volume backing %s for container %s: %s",
				mnt.kind, formatter.ContainerID{id}, err)
		}
	}

	if info.uidInfo.size != 0 {
		if err := mgr.subidAlloc.Free(id); err != nil {
			logrus.Errorf("rootfsMon: failed to free uid(gid) for container %s: %s",
				formatter.ContainerID{id}, err)
		}
	}

	logrus.Infof("released resources for container %s",
		formatter.ContainerID{id})
}

func (mgr *SysboxMgr) reqMounts(id, rootfs string, uid, gid uint32, shiftUids bool, reqList []ipcLib.MountReqInfo) ([]specs.Mount, error) {

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return nil, fmt.Errorf("container %s is not registered",
			formatter.ContainerID{id})
	}

	// if this is a stopped container that is being re-started, reuse its prior mounts
	if info.state == restarted {
		mounts := []specs.Mount{}
		for _, mntInfo := range info.mounts {
			mounts = append(mounts, mntInfo.mounts...)
		}
		return mounts, nil
	}

	// setup dirs that will be bind-mounted into container
	containerMnts := []specs.Mount{}
	mntInfos := []mountInfo{}

	for _, req := range reqList {
		var err error
		m := []specs.Mount{}

		switch req.Kind {

		case ipcLib.MntVarLibDocker:
			m, err = mgr.dockerVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, shiftUids, 0700)

		case ipcLib.MntVarLibKubelet:
			m, err = mgr.kubeletVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, shiftUids, 0755)

		case ipcLib.MntVarLibContainerdOvfs:
			m, err = mgr.containerdVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, shiftUids, 0700)

		default:
			err = fmt.Errorf("invalid mount request type: %s", req.Kind)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to setup mounts backing %s for container %s: %s", req.Dest,
				formatter.ContainerID{id}, err)
		}

		mntInfos = append(mntInfos, mountInfo{kind: req.Kind, mounts: m})
		containerMnts = append(containerMnts, m...)
	}

	// Add the linux kernel header mounts to the sys container. This is needed to
	// build or run apps that interact with the Linux kernel directly within a
	// sys container. Note that there is no need to track mntInfo for these since
	// we are not backing these with sysbox-mgr data stores.
	containerMnts = append(containerMnts, mgr.linuxHeaderMounts...)

	// Add the linux /lib/modules/<kernel> mounts to the sys
	// container. This allows system container processes to verify the
	// presence of modules via modprobe. System apps such as Docker and
	// K8s do this. Note that this does not imply module
	// loading/unloading is supported in a system container (it's
	// not). It merely lets processes check if a module is loaded.
	containerMnts = append(containerMnts, mgr.libModMounts...)

	if len(mntInfos) > 0 {
		info.rootfs = rootfs
		info.mounts = mntInfos

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	// Dispatch a thread that checks if the container will be auto-removed after it stops
	go mgr.autoRemoveCheck(id)

	return containerMnts, nil
}

// autoRemoveCheck finds out (best effort) if the container will be automatically
// removed after being stopped. This allows us to skip copying back the contents
// of the sysbox-mgr volumes to the container's rootfs when the container is stopped
// (such a copy would not make sense since the containers rootfs will be destroyed
// anyway).
func (mgr *SysboxMgr) autoRemoveCheck(id string) {

	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	if !found {
		mgr.ctLock.Unlock()
		return
	}
	mgr.ctLock.Unlock()

	logrus.Debugf("autoRemoveCheck: Docker query start for %s",
		formatter.ContainerID{id})

	timeout := time.Duration(3 * time.Second)

	docker, err := dockerUtils.DockerConnect(timeout)
	if err != nil {
		logrus.Debugf("autoRemoveCheck: Docker connection failed for %s: %s",
			formatter.ContainerID{id}, err)
		return
	}
	defer docker.Disconnect()

	ci, err := docker.ContainerGetInfo(id)
	if err != nil {
		logrus.Debugf("autoRemoveCheck: Docker query for %s failed: %s",
			formatter.ContainerID{id}, err)
		return
	}

	mgr.ctLock.Lock()
	info, found = mgr.contTable[id]
	if !found {
		mgr.ctLock.Unlock()
		return
	}

	info.autoRemove = ci.AutoRemove
	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	logrus.Debugf("autoRemoveCheck: done for %s (autoRemove = %v)",
		formatter.ContainerID{id}, info.autoRemove)
}

func (mgr *SysboxMgr) prepMounts(id string, uid, gid uint32, shiftUids bool, prepList []ipcLib.MountPrepInfo) (err error) {

	logrus.Debugf("preparing mounts for %s: %+v",
		formatter.ContainerID{id}, prepList)

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("container %s is not registered",
			formatter.ContainerID{id})
	}

	for _, prepInfo := range prepList {

		var origUid, origGid uint32
		src := prepInfo.Source

		// Exclusive mounts are mounts that should be mounted in one sys container at a
		// given time; it's OK if it's mounted in multiple containers, as long as only one
		// container uses it. If the mount is exclusive and another sys container has the
		// same mount source, exclMntTable.Add() will generate a warning.

		if prepInfo.Exclusive {
			mgr.exclMntTable.add(src, id)
			defer func() {
				if err != nil {
					mgr.exclMntTable.remove(src, id)
				}
			}()
		}

		// If uid shifting is enabled, check if the mount source has ownership matching that
		// of the container's root user. If not, modify the ownership of the mount source
		// accordingly.

		needChown := false

		if shiftUids {

			needChown, origUid, origGid, err = checkMntSrcOwnership(src, uid, gid)
			if err != nil {
				return fmt.Errorf("failed to check mount source ownership: %s", err)
			}

			if needChown {
				logrus.Infof("chowning %s to %d:%d for %s",
					src, uid, gid, formatter.ContainerID{id})

				if err = rChown(src, uid, gid); err != nil {
					return fmt.Errorf("failed to chown mount source at %s: %s", src, err)
				}

				logrus.Infof("done chowning %s for %s",
					src, formatter.ContainerID{id})
			}
		}

		// store the prep info so we can revert it when the container is stopped
		revInfo := mntPrepRevInfo{
			path:    src,
			chown:   needChown,
			origUid: origUid,
			origGid: origGid,
		}

		info.mntPrepRev = append(info.mntPrepRev, revInfo)
		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	logrus.Debugf("done preparing mounts for %s", formatter.ContainerID{id})

	return nil
}

func (mgr *SysboxMgr) allocSubid(id string, size uint64) (uint32, uint32, error) {

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return 0, 0, fmt.Errorf("container %s is not registered",
			formatter.ContainerID{id})
	}

	// if this is a newly started container, allocate the uid/gid range
	// (started or stopped containers keep their uid/gid range until removed)
	if info.uidInfo.size == 0 {
		uid, gid, err := mgr.subidAlloc.Alloc(id, size)
		if err != nil {
			return uid, gid, fmt.Errorf("failed to allocate uid(gid) for %s: %s",
				formatter.ContainerID{id}, err)
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
		return fmt.Errorf("container %s is not registered", formatter.ContainerID{id})
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

func (mgr *SysboxMgr) reqFsState(id, rootfs string) ([]configs.FsEntry, error) {

	// get container info
	mgr.ctLock.Lock()
	_, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return nil, fmt.Errorf("container %s is not registered", formatter.ContainerID{id})
	}

	var fsEntries []configs.FsEntry

	// In certain scenarios a soft-link will be required to properly resolve the
	// dependencies present in "/usr/src" and "/lib/modules/kernel" paths.
	entry, err := mgr.getKernelHeaderSoftlink(rootfs)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain kernel-headers softlink state for container %s: %s",
			formatter.ContainerID{id}, err)
	}
	if entry == nil {
		return nil, nil
	}

	fsEntries = append(fsEntries, *entry)

	return fsEntries, nil
}

func (mgr *SysboxMgr) getKernelHeaderSoftlink(rootfs string) (*configs.FsEntry, error) {

	// Obtain linux distro within the passed rootfs path. Notice that we are
	// not returning any received error to ensure we complete container's
	// registration in all scenarios (i.e. rootfs may not include a full linux
	// env -- it may miss os-release file).
	cntrDistro, err := libutils.GetDistroPath(rootfs)
	if err != nil {
		return nil, nil
	}

	// No need to proceed if host and container are running the same distro.
	if cntrDistro == mgr.hostDistro {
		return nil, nil
	}

	// Obtain container's kernel-header path.
	cntrKernelPath, err := libutils.GetLinuxHeaderPath(cntrDistro)
	if err != nil {
		return nil, fmt.Errorf("failed to identify kernel-header path of container's rootfs %s: %v",
			rootfs, err)
	}

	// Return if there's no kernelPath mismatch between host and container.
	if cntrKernelPath == mgr.hostKernelHdrPath {
		return nil, nil
	}

	// Create kernel-header softlink.
	fsEntry := configs.NewFsEntry(
		cntrKernelPath,
		mgr.hostKernelHdrPath,
		0644,
		configs.SoftlinkFsKind,
	)

	return fsEntry, nil
}

func (mgr *SysboxMgr) pause(id string) error {

	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("can't pause container %s; not found in container table",
			formatter.ContainerID{id})
	}

	// Request all volume managers to sync back contents to the container's rootfs
	for _, mnt := range info.mounts {
		var err error

		switch mnt.kind {

		case ipcLib.MntVarLibDocker:
			err = mgr.dockerVolMgr.SyncOut(id)

		case ipcLib.MntVarLibKubelet:
			err = mgr.kubeletVolMgr.SyncOut(id)

		case ipcLib.MntVarLibContainerdOvfs:
			err = mgr.containerdVolMgr.SyncOut(id)

		}
		if err != nil {
			return fmt.Errorf("sync-out for volume backing %s for container %s failed: %v",
				mnt.kind, formatter.ContainerID{id}, err)
		}
	}

	return nil
}

func preFlightCheck() error {
	for _, prog := range progDeps {
		if !utils.CmdExists(prog) {
			return fmt.Errorf("%s is not installed on host.", prog)
		}
	}
	return nil
}
