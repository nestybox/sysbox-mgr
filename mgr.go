//
// Copyright 2019-2022 Nestybox, Inc.
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
	"path"
	"sync"
	"time"

	systemd "github.com/coreos/go-systemd/daemon"
	"github.com/fsnotify/fsnotify"
	grpc "github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	"github.com/nestybox/sysbox-libs/dockerUtils"
	"github.com/nestybox/sysbox-libs/formatter"
	"github.com/nestybox/sysbox-libs/idMap"
	"github.com/nestybox/sysbox-libs/idShiftUtils"
	"github.com/nestybox/sysbox-libs/linuxUtils"
	libutils "github.com/nestybox/sysbox-libs/utils"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/rootfsCloner"
	"github.com/nestybox/sysbox-mgr/shiftfsMgr"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var sysboxLibDir string

type containerState int

const (
	started containerState = iota
	stopped
	restarted
)

type mntPrepRevInfo struct {
	path       string
	uidShifted bool
	origUid    uint32
	origGid    uint32
	targetUid  uint32
	targetGid  uint32
}

type mountInfo struct {
	kind   ipcLib.MntKind
	mounts []specs.Mount
}

type containerInfo struct {
	state          containerState
	rootfs         string
	mntPrepRev     []mntPrepRevInfo
	reqMntInfos    []mountInfo
	containerMnts  []specs.Mount
	shiftfsMarks   []configs.ShiftfsMount
	autoRemove     bool
	userns         string
	netns          string
	netnsInode     uint64
	uidMappings    []specs.LinuxIDMapping
	gidMappings    []specs.LinuxIDMapping
	subidAllocated bool
	rootfsCloned   bool
	origRootfs     string // if rootfs was cloned, this is the original rootfs
}

type mgrConfig struct {
	aliasDns                bool
	shiftfsOk               bool
	shiftfsOnOverlayfsOk    bool
	idMapMountOk            bool
	overlayfsOnIDMapMountOk bool
	noRootfsCloning         bool
	ignoreSysfsChown        bool
	allowTrustedXattr       bool
	honorCaps               bool
	syscontMode             bool
	fsuidMapFailOnErr       bool
}

type SysboxMgr struct {
	mgrCfg            mgrConfig
	grpcServer        *grpc.ServerStub
	subidAlloc        intf.SubidAlloc
	dockerVolMgr      intf.VolMgr
	kubeletVolMgr     intf.VolMgr
	k0sVolMgr         intf.VolMgr
	k3sVolMgr         intf.VolMgr
	rke2VolMgr        intf.VolMgr
	buildkitVolMgr    intf.VolMgr
	containerdVolMgr  intf.VolMgr
	shiftfsMgr        intf.ShiftfsMgr
	rootfsCloner      intf.RootfsCloner
	hostDistro        string
	hostKernelHdrPath string
	linuxHeaderMounts []specs.Mount
	libModMounts      []specs.Mount
	// Tracks containers known to sysbox (cont id -> cont info)
	contTable map[string]containerInfo
	ctLock    sync.Mutex
	// Tracks container rootfs (cont rootfs -> cont id); used by the rootfs monitor
	rootfsTable   map[string]string
	rtLock        sync.Mutex
	rootfsMonStop chan int
	rootfsWatcher *fsnotify.Watcher
	exclMntTable  *exclusiveMntTable
	// tracks containers using the same netns (netns inode -> list of container ids)
	netnsTable map[uint64][]string
	ntLock     sync.Mutex
}

// newSysboxMgr creates an instance of the sysbox manager
func newSysboxMgr(ctx *cli.Context) (*SysboxMgr, error) {
	var err error

	err = libutils.CheckPidFile("sysbox-mgr", sysboxMgrPidFile)
	if err != nil {
		return nil, err
	}

	err = preFlightCheck()
	if err != nil {
		return nil, fmt.Errorf("preflight check failed: %s", err)
	}

	sysboxLibDir = ctx.GlobalString("data-root")
	if sysboxLibDir == "" {
		sysboxLibDir = sysboxLibDirDefault
	}
	logrus.Infof("Sysbox data root: %s", sysboxLibDir)

	err = setupRunDir()
	if err != nil {
		return nil, fmt.Errorf("failed to setup the sysbox run dir: %v", err)
	}

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

	k0sVolMgr, err := setupK0sVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup k0s vol mgr: %v", err)
	}

	k3sVolMgr, err := setupK3sVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup k3s vol mgr: %v", err)
	}

	rke2VolMgr, err := setupRke2VolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup rke2 vol mgr: %v", err)
	}

	buildkitVolMgr, err := setupBuildkitVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup buildkit vol mgr: %v", err)
	}

	containerdVolMgr, err := setupContainerdVolMgr(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup containerd vol mgr: %v", err)
	}

	shiftfsMgr, err := shiftfsMgr.New(sysboxLibDir)
	if err != nil {
		return nil, fmt.Errorf("failed to setup shiftfs mgr: %v", err)
	}

	rootfsCloner := rootfsCloner.New(sysboxLibDir)
	if err != nil {
		return nil, fmt.Errorf("failed to setup rootfs mgr: %v", err)
	}

	hostDistro, err := linuxUtils.GetDistro()
	if err != nil {
		return nil, fmt.Errorf("failed to identify system's linux distribution: %v", err)
	}

	hostKernelHdrPath, err := linuxUtils.GetLinuxHeaderPath(hostDistro)
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

	idMapMountOk := false
	ovfsOnIDMapMountOk := false

	if !ctx.GlobalBool("disable-idmapped-mount") {
		idMapMountOk, ovfsOnIDMapMountOk, err = checkIDMapMountSupport(ctx)
		if err != nil {
			return nil, fmt.Errorf("ID-mapping check failed: %v", err)
		}
	}

	shiftfsModPresent := false
	shiftfsOk := false
	shiftfsOnOvfsOk := false

	if !ctx.GlobalBool("disable-shiftfs") {

		shiftfsModPresent, err = linuxUtils.KernelModSupported("shiftfs")
		if err != nil {
			return nil, fmt.Errorf("shiftfs kernel module check failed: %v", err)
		}

		if shiftfsModPresent {
			shiftfsOk, shiftfsOnOvfsOk, err = checkShiftfsSupport(ctx)
			if err != nil {
				return nil, fmt.Errorf("shiftfs check failed: %v", err)
			}
		}
	}

	mgrCfg := mgrConfig{
		aliasDns:                ctx.GlobalBoolT("alias-dns"),
		shiftfsOk:               shiftfsOk,
		shiftfsOnOverlayfsOk:    shiftfsOnOvfsOk,
		idMapMountOk:            idMapMountOk,
		overlayfsOnIDMapMountOk: ovfsOnIDMapMountOk,
		noRootfsCloning:         ctx.GlobalBool("disable-rootfs-cloning"),
		ignoreSysfsChown:        ctx.GlobalBool("ignore-sysfs-chown"),
		allowTrustedXattr:       ctx.GlobalBoolT("allow-trusted-xattr"),
		honorCaps:               ctx.GlobalBool("honor-caps"),
		syscontMode:             ctx.GlobalBoolT("syscont-mode"),
		fsuidMapFailOnErr:       ctx.GlobalBool("fsuid-map-fail-on-error"),
	}

	if !mgrCfg.aliasDns {
		logrus.Info("Sys container DNS aliasing disabled.")
	}

	if ctx.GlobalBool("disable-shiftfs") {
		logrus.Info("Use of shiftfs disabled.")
	} else {
		logrus.Infof("Shiftfs module found in kernel: %s", ifThenElse(shiftfsModPresent, "yes", "no"))
		logrus.Infof("Shiftfs works properly: %s", ifThenElse(mgrCfg.shiftfsOk, "yes", "no"))
		logrus.Infof("Shiftfs-on-overlayfs works properly: %s", ifThenElse(mgrCfg.shiftfsOnOverlayfsOk, "yes", "no"))
	}

	if ctx.GlobalBool("disable-idmapped-mount") {
		logrus.Info("Use of ID-mapped mounts disabled.")
	} else {
		logrus.Infof("ID-mapped mounts supported by kernel: %s", ifThenElse(mgrCfg.idMapMountOk, "yes", "no"))
		logrus.Infof("Overlayfs on ID-mapped mounts supported by kernel: %s", ifThenElse(mgrCfg.overlayfsOnIDMapMountOk, "yes", "no"))
	}

	if mgrCfg.noRootfsCloning {
		logrus.Info("Rootfs cloning disabled.")
	}

	if mgrCfg.ignoreSysfsChown {
		logrus.Info("Ignoring chown of /sys inside container.")
	}

	if !mgrCfg.allowTrustedXattr {
		logrus.Info("Disallowing trusted.overlay.opaque inside container.")
	}

	if mgrCfg.honorCaps {
		logrus.Info("Honoring process capabilities in OCI spec (--honor-caps).")
	}

	if mgrCfg.syscontMode {
		logrus.Info("Operating in system container mode.")
	} else {
		logrus.Info("Operating in regular container mode.")
	}

	if mgrCfg.fsuidMapFailOnErr {
		logrus.Info("fsuid-map-fail-on-error = true.")
	}

	mgr := &SysboxMgr{
		mgrCfg:            mgrCfg,
		subidAlloc:        subidAlloc,
		dockerVolMgr:      dockerVolMgr,
		kubeletVolMgr:     kubeletVolMgr,
		k0sVolMgr:         k0sVolMgr,
		k3sVolMgr:         k3sVolMgr,
		rke2VolMgr:        rke2VolMgr,
		buildkitVolMgr:    buildkitVolMgr,
		containerdVolMgr:  containerdVolMgr,
		shiftfsMgr:        shiftfsMgr,
		rootfsCloner:      rootfsCloner,
		hostDistro:        hostDistro,
		hostKernelHdrPath: hostKernelHdrPath,
		linuxHeaderMounts: linuxHeaderMounts,
		libModMounts:      libModMounts,
		contTable:         make(map[string]containerInfo),
		rootfsTable:       make(map[string]string),
		rootfsMonStop:     make(chan int),
		netnsTable:        make(map[uint64][]string),
		exclMntTable:      newExclusiveMntTable(),
	}

	cb := &grpc.ServerCallbacks{
		Register:                mgr.register,
		Update:                  mgr.update,
		Unregister:              mgr.unregister,
		SubidAlloc:              mgr.allocSubid,
		ReqMounts:               mgr.reqMounts,
		PrepMounts:              mgr.prepMounts,
		ReqShiftfsMark:          mgr.reqShiftfsMark,
		ReqFsState:              mgr.reqFsState,
		CloneRootfs:             mgr.cloneRootfs,
		ChownClonedRootfs:       mgr.chownClonedRootfs,
		RevertClonedRootfsChown: mgr.revertClonedRootfsChown,
		Pause:                   mgr.pause,
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

	systemd.SdNotify(false, systemd.SdNotifyReady)

	err = libutils.CreatePidFile("sysbox-mgr", sysboxMgrPidFile)
	if err != nil {
		return fmt.Errorf("failed to create sysmgr.pid file: %s", err)
	}

	logrus.Info("Ready ...")

	// listen for grpc connections
	return mgr.grpcServer.Init()
}

func (mgr *SysboxMgr) Stop() error {

	logrus.Info("Stopping (gracefully) ...")

	systemd.SdNotify(false, systemd.SdNotifyStopping)

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
	mgr.k0sVolMgr.SyncOutAndDestroyAll()
	mgr.k3sVolMgr.SyncOutAndDestroyAll()
	mgr.rke2VolMgr.SyncOutAndDestroyAll()
	mgr.buildkitVolMgr.SyncOutAndDestroyAll()
	mgr.containerdVolMgr.SyncOutAndDestroyAll()
	mgr.shiftfsMgr.UnmarkAll()

	// Note: this will cause the container's cloned rootfs to be removed when
	// Sysbox is stopped, thus loosing the container's runtime data. In the
	// future we may want to make this persistent across Sysbox stop-restart
	// events.
	mgr.rootfsCloner.RemoveAll()

	if err := cleanupWorkDirs(); err != nil {
		logrus.Warnf("failed to cleanup work dirs: %v", err)
	}

	if err := libutils.DestroyPidFile(sysboxMgrPidFile); err != nil {
		logrus.Warnf("failed to destroy sysbox-mgr pid file: %v", err)
	}

	logrus.Info("Stopped.")

	return nil
}

// Registers a container with sysbox-mgr
func (mgr *SysboxMgr) register(regInfo *ipcLib.RegistrationInfo) (*ipcLib.ContainerConfig, error) {

	id := regInfo.Id
	rootfs := regInfo.Rootfs
	userns := regInfo.Userns
	netns := regInfo.Netns
	uidMappings := regInfo.UidMappings
	gidMappings := regInfo.GidMappings

	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]

	if !found {
		// new container
		info = containerInfo{
			state:        started,
			mntPrepRev:   []mntPrepRevInfo{},
			shiftfsMarks: []configs.ShiftfsMount{},
		}
	} else {
		// re-started container
		if info.state != stopped {
			mgr.ctLock.Unlock()
			return nil, fmt.Errorf("redundant container registration for container %s",
				formatter.ContainerID{id})
		}
		info.state = restarted
	}

	if !info.rootfsCloned {
		info.rootfs = rootfs
		info.origRootfs = rootfs
	}

	info.netns = netns
	info.userns = userns

	if !info.subidAllocated {
		info.uidMappings = uidMappings
		info.gidMappings = gidMappings
	}

	// Track the container's net-ns, so we can later determine if multiple sys
	// containers are sharing a net-ns (which implies they share the user-ns too).
	var sameNetns []string

	if netns != "" {
		netnsInode, err := getInode(netns)
		if err != nil {
			mgr.ctLock.Unlock()
			return nil, fmt.Errorf("unable to get inode for netns %s: %s", netns, err)
		}

		sameNetns, err = mgr.trackNetns(id, netnsInode)
		if err != nil {
			mgr.ctLock.Unlock()
			return nil, fmt.Errorf("failed to track netns for container %s: %s",
				formatter.ContainerID{id}, err)
		}

		info.netnsInode = netnsInode
	}

	// If this container's netns is shared with other containers, it's userns
	// (and associated ID mappings) must be shared too.
	if len(sameNetns) > 1 && userns == "" {
		otherContSameNetnsInfo, ok := mgr.contTable[sameNetns[0]]
		if !ok {
			mgr.ctLock.Unlock()
			return nil,
				fmt.Errorf("container %s shares net-ns with other containers, but unable to find info for those.",
					formatter.ContainerID{id})
		}
		info.userns = otherContSameNetnsInfo.userns
		info.uidMappings = otherContSameNetnsInfo.uidMappings
		info.gidMappings = otherContSameNetnsInfo.gidMappings
	}

	mgr.contTable[id] = info
	mgr.ctLock.Unlock()

	if info.state == restarted {
		if info.origRootfs != "" {
			// remove the container's rootfs watch
			origRootfs := sanitizeRootfs(id, info.origRootfs)
			mgr.rootfsWatcher.Remove(origRootfs)
			mgr.rtLock.Lock()
			delete(mgr.rootfsTable, origRootfs)
			mgr.rtLock.Unlock()
			logrus.Debugf("removed fs watch on %s", origRootfs)
		}

		logrus.Infof("registered container %s", formatter.ContainerID{id})
	} else {
		logrus.Infof("registered new container %s", formatter.ContainerID{id})
	}

	containerCfg := &ipcLib.ContainerConfig{
		AliasDns:                mgr.mgrCfg.aliasDns,
		ShiftfsOk:               mgr.mgrCfg.shiftfsOk,
		ShiftfsOnOverlayfsOk:    mgr.mgrCfg.shiftfsOnOverlayfsOk,
		IDMapMountOk:            mgr.mgrCfg.idMapMountOk,
		OverlayfsOnIDMapMountOk: mgr.mgrCfg.overlayfsOnIDMapMountOk,
		NoRootfsCloning:         mgr.mgrCfg.noRootfsCloning,
		IgnoreSysfsChown:        mgr.mgrCfg.ignoreSysfsChown,
		AllowTrustedXattr:       mgr.mgrCfg.allowTrustedXattr,
		HonorCaps:               mgr.mgrCfg.honorCaps,
		SyscontMode:             mgr.mgrCfg.syscontMode,
		FsuidMapFailOnErr:       mgr.mgrCfg.fsuidMapFailOnErr,
		Userns:                  info.userns,
		UidMappings:             info.uidMappings,
		GidMappings:             info.gidMappings,
	}

	return containerCfg, nil
}

// Updates info for a given container
func (mgr *SysboxMgr) update(updateInfo *ipcLib.UpdateInfo) error {

	id := updateInfo.Id
	userns := updateInfo.Userns
	netns := updateInfo.Netns
	uidMappings := updateInfo.UidMappings
	gidMappings := updateInfo.GidMappings

	mgr.ctLock.Lock()
	defer mgr.ctLock.Unlock()

	info, found := mgr.contTable[id]
	if !found {
		return fmt.Errorf("can't update container %s; not found in container table",
			formatter.ContainerID{id})
	}

	if info.netns == "" && netns != "" {
		netnsInode, err := getInode(netns)
		if err != nil {
			return fmt.Errorf("can't update container %s: unable to get inode for netns %s: %s",
				formatter.ContainerID{id}, netns, err)
		}

		if _, err := mgr.trackNetns(id, netnsInode); err != nil {
			return fmt.Errorf("can't update container %s: failed to track netns: %s",
				formatter.ContainerID{id}, err)
		}
		info.netns = netns
		info.netnsInode = netnsInode
	}

	if info.userns == "" && userns != "" {
		info.userns = userns
	}

	if len(info.uidMappings) == 0 && len(uidMappings) > 0 {
		info.uidMappings = uidMappings
	}

	if len(info.gidMappings) == 0 && len(gidMappings) > 0 {
		info.gidMappings = gidMappings
	}

	mgr.contTable[id] = info
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
		if revInfo.uidShifted {

			uidOffset := int32(revInfo.origUid) - int32(revInfo.targetUid)
			gidOffset := int32(revInfo.origGid) - int32(revInfo.targetGid)

			logrus.Infof("reverting uid-shift on %s for %s (%d -> %d)", revInfo.path, formatter.ContainerID{id}, revInfo.targetUid, revInfo.origUid)

			if err = idShiftUtils.ShiftIdsWithChown(revInfo.path, uidOffset, gidOffset); err != nil {
				logrus.Warnf("failed to revert uid-shift of mount source at %s: %s", revInfo.path, err)
			}

			logrus.Infof("done reverting uid-shift on %s for %s", revInfo.path, formatter.ContainerID{id})
		}

		mgr.exclMntTable.remove(revInfo.path, id)
	}
	info.mntPrepRev = []mntPrepRevInfo{}

	// update the netns sharing table
	//
	// note: we don't do error checking because this can fail if the netns is not
	// yet tracked for the container (e.g., if a container is registered and
	// then unregistered because the container failed to start for some reason).
	mgr.untrackNetns(id, info.netnsInode)

	// ns tracking info is reset for new or restarted containers
	info.userns = ""
	info.netns = ""
	info.netnsInode = 0

	// uid mappings for the container are also reset, except if they were
	// allocated by sysbox-mgr (those are kept across container restarts).
	if !info.subidAllocated {
		info.uidMappings = nil
		info.gidMappings = nil
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

	// Notify rootfs cloner that container has stopped
	if info.rootfsCloned {
		if err := mgr.rootfsCloner.ContainerStopped(id); err != nil {
			return err
		}
	}

	// setup a rootfs watch (allows us to get notified when the container's rootfs is removed)
	if info.origRootfs != "" {
		origRootfs := sanitizeRootfs(id, info.origRootfs)

		mgr.rtLock.Lock()
		mgr.rootfsTable[origRootfs] = id
		mgr.rootfsWatcher.Add(origRootfs)

		// It may be the case that original rootfs has been deleted by the time we
		// tell the rootfsWatcher, which means the watcher won't catch the rootfs
		// removal event. In this case, let's cancel the watch event and remove
		// the sysbox-mgr state for the container.

		if _, err := os.Stat(origRootfs); os.IsNotExist(err) {
			delete(mgr.rootfsTable, origRootfs)
			mgr.rootfsWatcher.Remove(origRootfs)
			mgr.rtLock.Unlock()
			mgr.removeCont(id)
			return nil
		}

		mgr.rtLock.Unlock()
		logrus.Debugf("added fs watch on %s", origRootfs)
	}

	logrus.Infof("unregistered container %s", formatter.ContainerID{id})
	return nil
}

func (mgr *SysboxMgr) volSyncOut(id string, info containerInfo) error {
	var err, err2 error
	failedVols := []string{}

	for _, mnt := range info.reqMntInfos {
		switch mnt.kind {
		case ipcLib.MntVarLibDocker:
			err = mgr.dockerVolMgr.SyncOut(id)
		case ipcLib.MntVarLibKubelet:
			err = mgr.kubeletVolMgr.SyncOut(id)
		case ipcLib.MntVarLibK0s:
			err = mgr.k0sVolMgr.SyncOut(id)
		case ipcLib.MntVarLibRancherK3s:
			err = mgr.k3sVolMgr.SyncOut(id)
		case ipcLib.MntVarLibRancherRke2:
			err = mgr.rke2VolMgr.SyncOut(id)
		case ipcLib.MntVarLibBuildkit:
			err = mgr.buildkitVolMgr.SyncOut(id)
		case ipcLib.MntVarLibContainerdOvfs:
			err = mgr.containerdVolMgr.SyncOut(id)
		}

		if err != nil {
			failedVols = append(failedVols, mnt.kind.String())
			err2 = err
		}
	}

	if len(failedVols) > 0 {
		return fmt.Errorf("sync-out for volume backing %s: %v", failedVols, err2)
	}

	return nil
}

// rootfs monitor thread: checks for rootfs removal event and removes container state.
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

	for _, mnt := range info.reqMntInfos {
		var err error

		switch mnt.kind {

		case ipcLib.MntVarLibDocker:
			err = mgr.dockerVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibKubelet:
			err = mgr.kubeletVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibK0s:
			err = mgr.k0sVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibRancherK3s:
			err = mgr.k3sVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibRancherRke2:
			err = mgr.rke2VolMgr.DestroyVol(id)

		case ipcLib.MntVarLibBuildkit:
			err = mgr.buildkitVolMgr.DestroyVol(id)

		case ipcLib.MntVarLibContainerdOvfs:
			err = mgr.containerdVolMgr.DestroyVol(id)

		}
		if err != nil {
			logrus.Errorf("rootfsMon: failed to destroy volume backing %s for container %s: %s",
				mnt.kind, formatter.ContainerID{id}, err)
		}
	}

	if info.subidAllocated {
		if err := mgr.subidAlloc.Free(id); err != nil {
			logrus.Errorf("rootfsMon: failed to free uid(gid) for container %s: %s",
				formatter.ContainerID{id}, err)
		}
	}

	if info.rootfsCloned {
		if err := mgr.rootfsCloner.RemoveClone(id); err != nil {
			logrus.Warnf("failed to unbind cloned rootfs for container %s: %s",
				formatter.ContainerID{id}, err)
		}
	}

	logrus.Infof("released resources for container %s",
		formatter.ContainerID{id})
}

func (mgr *SysboxMgr) reqMounts(id string, uid, gid uint32, reqList []ipcLib.MountReqInfo) ([]specs.Mount, error) {

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
		return info.containerMnts, nil
	}

	// setup dirs that will be bind-mounted into the container
	containerMnts := []specs.Mount{}
	reqMntInfos := []mountInfo{}
	rootfs := info.rootfs

	for _, req := range reqList {
		var err error
		m := []specs.Mount{}

		switch req.Kind {

		case ipcLib.MntVarLibDocker:
			m, err = mgr.dockerVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0700)

		case ipcLib.MntVarLibKubelet:
			m, err = mgr.kubeletVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0755)

		case ipcLib.MntVarLibK0s:
			m, err = mgr.k0sVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0755)

		case ipcLib.MntVarLibRancherK3s:
			m, err = mgr.k3sVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0755)

		case ipcLib.MntVarLibRancherRke2:
			m, err = mgr.rke2VolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0755)

		case ipcLib.MntVarLibBuildkit:
			m, err = mgr.buildkitVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0755)

		case ipcLib.MntVarLibContainerdOvfs:
			m, err = mgr.containerdVolMgr.CreateVol(id, rootfs, req.Dest, uid, gid, req.ShiftUids, 0700)

		default:
			err = fmt.Errorf("invalid mount request type: %s", req.Kind)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to setup mounts backing %s for container %s: %s", req.Dest,
				formatter.ContainerID{id}, err)
		}

		reqMntInfos = append(reqMntInfos, mountInfo{kind: req.Kind, mounts: m})
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

	if len(reqMntInfos) > 0 {
		info.reqMntInfos = reqMntInfos
		info.containerMnts = containerMnts

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

func (mgr *SysboxMgr) prepMounts(id string, uid, gid uint32, prepList []ipcLib.MountPrepInfo) (err error) {

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
		src := prepInfo.Source

		// Exclusive mounts are mounts that should be mounted in one sys container at a
		// given time; it's OK if it's mounted in multiple containers, as long as only one
		// container uses it. If the mount is exclusive and another sys container has the
		// same mount source, exclMntTable.add() will generate a warning.
		exclMountInUse := false
		if prepInfo.Exclusive {
			exclMountInUse = mgr.exclMntTable.add(src, id)
			defer func() {
				if err != nil {
					mgr.exclMntTable.remove(src, id)
				}
			}()
		}

		// If the mount can be ID-mapped, nothing else to do
		if mgr.mgrCfg.overlayfsOnIDMapMountOk {
			useIDMap, err := idMap.IDMapMountSupportedOnPath(src)
			if err != nil {
				return err
			}
			if useIDMap {
				continue
			}
		}

		// The mount can't be ID-mapped, we may need to chown it; check if the
		// mount source has ownership matching that of the container's root
		// user. If not, chown it the mount source accordingly. Skip this if the
		// mount is already in use by another container (to avoid messing up the
		// ownership of the mount).
		needUidShift, origUid, origGid, err := mntSrcUidShiftNeeded(src, uid, gid)
		if err != nil {
			return fmt.Errorf("failed to check mount source ownership: %s", err)
		}

		if needUidShift {
			if !exclMountInUse {
				// Offset may be positive or negative
				uidOffset := int32(uid) - int32(origUid)
				gidOffset := int32(gid) - int32(origGid)

				logrus.Infof("shifting uids at %s for %s (%d -> %d)", src, formatter.ContainerID{id}, origUid, uid)

				if err = idShiftUtils.ShiftIdsWithChown(src, uidOffset, gidOffset); err != nil {
					return fmt.Errorf("failed to shift uids via chown for mount source at %s: %s", src, err)
				}

				logrus.Infof("done shifting uids at %s for %s", src, formatter.ContainerID{id})
			} else {
				logrus.Infof("skip shifting uids at %s for %s (mount is in use by another container)", src, formatter.ContainerID{id})
			}
		}

		// store the prep info so we can revert it when the container is stopped
		revInfo := mntPrepRevInfo{
			path:       src,
			uidShifted: needUidShift,
			origUid:    origUid,
			origGid:    origGid,
			targetUid:  uid,
			targetGid:  gid,
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

	// If we are being asked to allocate ID mappings for a new container, do it.
	// For restarted containers, we keep the mappings we had prior to the
	// container being stopped.
	if !info.subidAllocated {

		uid, gid, err := mgr.subidAlloc.Alloc(id, size)
		if err != nil {
			return uid, gid, fmt.Errorf("failed to allocate uid(gid) for %s: %s",
				formatter.ContainerID{id}, err)
		}

		uidMapping := specs.LinuxIDMapping{
			ContainerID: 0,
			HostID:      uid,
			Size:        uint32(size),
		}

		gidMapping := specs.LinuxIDMapping{
			ContainerID: 0,
			HostID:      gid,
			Size:        uint32(size),
		}

		info.uidMappings = append(info.uidMappings, uidMapping)
		info.gidMappings = append(info.gidMappings, gidMapping)
		info.subidAllocated = true

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return info.uidMappings[0].HostID, info.gidMappings[0].HostID, nil
}

func (mgr *SysboxMgr) reqShiftfsMark(id string, mounts []configs.ShiftfsMount) ([]configs.ShiftfsMount, error) {

	// get container info
	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return nil, fmt.Errorf("container %s is not registered", formatter.ContainerID{id})
	}

	if len(info.shiftfsMarks) == 0 {
		markpoints, err := mgr.shiftfsMgr.Mark(id, mounts, true)
		if err != nil {
			return nil, err
		}

		info.shiftfsMarks = markpoints

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return info.shiftfsMarks, nil
}

func (mgr *SysboxMgr) reqFsState(id, rootfs string) ([]configs.FsEntry, error) {

	// get container info
	mgr.ctLock.Lock()
	_, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return nil, fmt.Errorf("container %s is not registered", formatter.ContainerID{id})
	}

	if len(mgr.linuxHeaderMounts) == 0 {
		return nil, nil
	}

	// In certain scenarios a soft-link will be required to properly resolve the
	// dependencies present in "/usr/src" and "/lib/modules/kernel" paths.
	fsEntries, err := mgr.getKernelHeaderSoftlink(rootfs)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain kernel-headers softlink state for container %s: %s",
			formatter.ContainerID{id}, err)
	}

	return fsEntries, nil
}

func (mgr *SysboxMgr) getKernelHeaderSoftlink(rootfs string) ([]configs.FsEntry, error) {

	// Obtain linux distro within the passed rootfs path. Notice that we are
	// not returning any received error to ensure we complete container's
	// registration in all scenarios (i.e. rootfs may not include a full linux
	// env -- it may miss os-release file).
	cntrDistro, err := linuxUtils.GetDistroPath(rootfs)
	if err != nil {
		return nil, nil
	}

	// No need to proceed if host and container are running the same distro.
	if cntrDistro == mgr.hostDistro {
		return nil, nil
	}

	// Obtain container's kernel-header path.
	cntrKernelPath, err := linuxUtils.GetLinuxHeaderPath(cntrDistro)
	if err != nil {
		return nil, fmt.Errorf("failed to identify kernel-header path of container's rootfs %s: %v",
			rootfs, err)
	}

	// Return if there's no kernelPath mismatch between host and container.
	if cntrKernelPath == mgr.hostKernelHdrPath {
		return nil, nil
	}

	var fsEntries []configs.FsEntry

	// In certain distros, such as 'alpine', the kernel header path (typically
	// "/usr/src") may not exist, so create an associated fsEntry to ensure
	// that the kernel softlink addition (below) can be properly carried out.
	fsEntryParents := configs.NewFsEntry(
		path.Dir(cntrKernelPath),
		"",
		0755,
		configs.DirFsKind,
	)

	// Create kernel-header softlink.
	fsEntry := configs.NewFsEntry(
		cntrKernelPath,
		mgr.hostKernelHdrPath,
		0644,
		configs.SoftlinkFsKind,
	)

	fsEntries = append(fsEntries, *fsEntryParents, *fsEntry)

	return fsEntries, nil
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
	for _, mnt := range info.reqMntInfos {
		var err error

		switch mnt.kind {

		case ipcLib.MntVarLibDocker:
			err = mgr.dockerVolMgr.SyncOut(id)

		case ipcLib.MntVarLibKubelet:
			err = mgr.kubeletVolMgr.SyncOut(id)

		case ipcLib.MntVarLibK0s:
			err = mgr.k0sVolMgr.SyncOut(id)

		case ipcLib.MntVarLibRancherK3s:
			err = mgr.k3sVolMgr.SyncOut(id)

		case ipcLib.MntVarLibRancherRke2:
			err = mgr.rke2VolMgr.SyncOut(id)

		case ipcLib.MntVarLibBuildkit:
			err = mgr.buildkitVolMgr.SyncOut(id)

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

// trackNetns tracks the network ns for the given container id
func (mgr *SysboxMgr) trackNetns(id string, netnsInode uint64) ([]string, error) {

	mgr.ntLock.Lock()
	defer mgr.ntLock.Unlock()

	sameNetns, ok := mgr.netnsTable[netnsInode]
	if ok {
		sameNetns = append(sameNetns, id)
	} else {
		sameNetns = []string{id}
	}

	mgr.netnsTable[netnsInode] = sameNetns

	return sameNetns, nil
}

// untrackNetns removes netns tracking for the given container id
func (mgr *SysboxMgr) untrackNetns(id string, netnsInode uint64) error {
	mgr.ntLock.Lock()
	defer mgr.ntLock.Unlock()

	sameNetns, ok := mgr.netnsTable[netnsInode]
	if !ok {
		return fmt.Errorf("did not find inode %d in netnsTable", netnsInode)
	}

	sameNetns = libutils.StringSliceRemove(sameNetns, []string{id})

	if len(sameNetns) > 0 {
		mgr.netnsTable[netnsInode] = sameNetns
	} else {
		delete(mgr.netnsTable, netnsInode)
	}

	return nil
}

func (mgr *SysboxMgr) cloneRootfs(id string) (string, error) {

	mgr.ctLock.Lock()
	info, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return "", fmt.Errorf("container %s is not registered",
			formatter.ContainerID{id})
	}

	rmgr := mgr.rootfsCloner

	if !info.rootfsCloned {

		clonedRootfs, err := rmgr.CreateClone(id, info.rootfs)
		if err != nil {
			return "", err
		}

		info.rootfs = clonedRootfs
		info.rootfsCloned = true

		mgr.ctLock.Lock()
		mgr.contTable[id] = info
		mgr.ctLock.Unlock()
	}

	return info.rootfs, nil
}

func (mgr *SysboxMgr) chownClonedRootfs(id string, uidOffset, gidOffset int32) error {

	mgr.ctLock.Lock()
	_, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("container %s is not registered",
			formatter.ContainerID{id})
	}

	rmgr := mgr.rootfsCloner

	return rmgr.ChownClone(id, uidOffset, gidOffset)
}

func (mgr *SysboxMgr) revertClonedRootfsChown(id string) error {

	mgr.ctLock.Lock()
	_, found := mgr.contTable[id]
	mgr.ctLock.Unlock()

	if !found {
		return fmt.Errorf("container %s is not registered",
			formatter.ContainerID{id})
	}

	rmgr := mgr.rootfsCloner

	return rmgr.RevertChown(id)
}
