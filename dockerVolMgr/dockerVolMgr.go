//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

// The docker volume manager (dockerVolMgr) manages volumes that are mounted into the
// /var/lib/docker directory of each sys container, with the goal of ensuring that a
// Docker engine inside the sys container runs without problems (e.g., by avoiding
// overlayfs-on-overlayfs mounts).
//
// The dockerVolMgr operates as follows:
//
// When a sys container is started, the dockerVolMgr creates a host directory that is
// mounted (by sysbox-runc) into the sys container's /var/lib/docker directory. If the sys
// container comes preloaded with inner docker images in its rootfs dir, the dockerVolMgr
// copies the inner images to the host directory.
//
// When a sys container is stopped or paused, the dockerVolMgr copies the contents of the
// host directory back to the sys container's rootfs dir. When the sys container is
// destroyed, the dockerVolMgr destroys the host directory.
//
// The copying described above can cause significant delays and storage overhead when a
// sys container image is preloaded with heavy inner container images. To mitigate this
// overhead, the dockerVolMgr supports a technique that allows multiple sys containers to
// share the same inner images using copy-on-write (COW). This causes the overhead to
// occur for the first container associated with a given image, but avoids it for all
// subsequent containers associated with the same image. It can easily save GBs of storage
// overhead and reduce container start time by a few seconds.
//
// Currently, the COW technique is only supported when the inner docker is configured with
// the overlayfs storage driver (which is Docker's default storage driver). It's not yet
// supported for other storage drivers. It can also be disabled when instantiating the
// dockerVolMgr.

package dockerVolMgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	dockerRoot   = "/var/lib/docker"
	dockerImgDir = "overlay2"
	mgrPerm      = 0700
)

// volume info (per container)
type volInfo struct {
	basePath  string      // base volume path
	rootfs    string      // container rootfs
	contPath  string      // container path where base volume is mounted
	uid       uint32      // uid owner for the volume
	gid       uint32      // gid owner for the volume
	shiftUids bool        // uid(gid) shifting enabled for the volume
	perm      os.FileMode // permissions for the volume
	cowPath   string      // cow volume path (for image sharing)
	imgID     string      // container image (for image sharing)
}

// inner-docker image volume info (per container image)
type imgVolInfo struct {
	volPath     string // img vol path
	contImgPath string // container image path where images where copied from
	refCnt      int    // containers using this image
}

type dockerVolMgr struct {
	innerImgSharing bool
	workspace       string
	baseVolDir      string
	imgVolDir       string
	cowVolDir       string
	volTable        map[string]*volInfo    // container id -> volInfo
	imgTable        map[string]*imgVolInfo // image id -> imgVolInfo
	volTableMu      sync.Mutex
	imgTableMu      sync.Mutex
}

// Creates a new instance of the dockerVolMgr
func New(workspace string, innerImgSharing bool) (intf.VolMgr, error) {
	var err error

	mgr := &dockerVolMgr{
		workspace:       workspace,
		innerImgSharing: innerImgSharing,
		volTable:        make(map[string]*volInfo),
	}

	mgr.baseVolDir = filepath.Join(workspace, "baseVol")
	if err = os.Mkdir(mgr.baseVolDir, mgrPerm); err != nil {
		return nil, fmt.Errorf("failed to create %s: %s", mgr.baseVolDir, err)
	}

	if innerImgSharing {
		mgr.imgTable = make(map[string]*imgVolInfo)

		mgr.imgVolDir = filepath.Join(workspace, "imgVol")
		if err = os.Mkdir(mgr.imgVolDir, mgrPerm); err != nil {
			os.RemoveAll(mgr.baseVolDir)
			return nil, fmt.Errorf("failed to create %s: %s", mgr.imgVolDir, err)
		}

		mgr.cowVolDir = filepath.Join(workspace, "cowVol")
		if err = os.Mkdir(mgr.cowVolDir, mgrPerm); err != nil {
			os.RemoveAll(mgr.baseVolDir)
			os.RemoveAll(mgr.imgVolDir)
			return nil, fmt.Errorf("failed to create %s: %s", mgr.cowVolDir, err)
		}
	}

	return mgr, nil
}

// Implements intf.VolMgr.CreateVol
func (mgr *dockerVolMgr) CreateVol(id, rootfs, mountpoint string, uid, gid uint32, shiftUids bool, perm os.FileMode) ([]specs.Mount, error) {
	var err error

	mgr.volTableMu.Lock()
	if _, found := mgr.volTable[id]; found {
		mgr.volTableMu.Unlock()
		return nil, fmt.Errorf("volume for %s already exists", id)
	}
	mgr.volTableMu.Unlock()

	vi := &volInfo{
		basePath:  filepath.Join(mgr.baseVolDir, id),
		rootfs:    rootfs,
		contPath:  filepath.Join(rootfs, mountpoint),
		uid:       uid,
		gid:       gid,
		shiftUids: shiftUids,
		perm:      perm,
	}

	imgVolMounts := []specs.Mount{}

	innerImg, err := syscontHasInnerImg(rootfs)
	if err != nil {
		return nil, fmt.Errorf("failed to check if container has inner images: %v", err)
	}

	// We support inner container image sharing for containers that have inner images.
	if mgr.innerImgSharing && innerImg {
		imgID, err := getContainerImage(id)
		if err == nil {
			imgVolMounts, err = mgr.setupImgSharing(id, imgID, vi)
			if err != nil {
				return nil, fmt.Errorf("failed to setup image sharing for %s: %s", id, err)
			}
			vi.imgID = imgID
		}
	}

	imgSharing := false
	if len(imgVolMounts) > 0 {
		imgSharing = true
	}

	baseVolMount, err := mgr.createBaseVol(id, mountpoint, vi, imgSharing)
	if err != nil {
		if imgSharing {
			mgr.teardownImgSharing(id, vi)
		}
		return nil, fmt.Errorf("failed to create docker vol for %s: %s", id, err)
	}

	mgr.volTableMu.Lock()
	mgr.volTable[id] = vi
	mgr.volTableMu.Unlock()

	mounts := []specs.Mount{}
	mounts = append(mounts, baseVolMount...)
	mounts = append(mounts, imgVolMounts...)

	return mounts, nil
}

// Implements intf.VolMgr.DestroyVol
func (mgr *dockerVolMgr) DestroyVol(id string) error {

	mgr.volTableMu.Lock()
	vi, found := mgr.volTable[id]
	if !found {
		mgr.volTableMu.Unlock()
		return fmt.Errorf("invalid id %s", id)
	}
	mgr.volTableMu.Unlock()

	if mgr.innerImgSharing {
		if vi.imgID != "" {
			if err := mgr.teardownImgSharing(id, vi); err != nil {
				return fmt.Errorf("failed to teardown image sharing for %s: %s", id, err)
			}
		}
	}

	if err := mgr.destroyBaseVol(id, vi); err != nil {
		return fmt.Errorf("failed to destroy docker vol for %s: %s", id, err)
	}

	mgr.volTableMu.Lock()
	delete(mgr.volTable, id)
	mgr.volTableMu.Unlock()

	return nil
}

// Implements intf.VolMgr.SyncOut
func (mgr *dockerVolMgr) SyncOut(id string) error {

	mgr.volTableMu.Lock()
	vi, found := mgr.volTable[id]
	if !found {
		mgr.volTableMu.Unlock()
		return fmt.Errorf("invalid id %s", id)
	}
	mgr.volTableMu.Unlock()

	skipImgCopy := false
	if vi.cowPath != "" {
		skipImgCopy = true
	}

	if err := mgr.syncOutBaseVol(id, vi, skipImgCopy); err != nil {
		return err
	}

	if skipImgCopy {
		if err := mgr.syncOutCowVol(id, vi); err != nil {
			return err
		}
	}

	return nil
}

// Implements intf.VolMgr.SyncOutAndDestroyAll
func (mgr *dockerVolMgr) SyncOutAndDestroyAll() {
	for id, _ := range mgr.volTable {
		if err := mgr.SyncOut(id); err != nil {
			logrus.Warnf("failed to sync-out volumes for container %s: %s", id, err)
		}
		if err := mgr.DestroyVol(id); err != nil {
			logrus.Warnf("failed to destroy volumes for container %s: %s", id, err)
		}
	}
}

// Creates the base volume to back the given sys container's /var/lib/docker. Copies the
// contents of the container's /var/lib/docker (if any) to the newly created volume. If
// skipImgCopy is true, the copy skips any inner container images under /var/lib/docker.
func (mgr *dockerVolMgr) createBaseVol(id string, mountpoint string, vi *volInfo, skipImgCopy bool) ([]specs.Mount, error) {
	var err error

	if err = os.Mkdir(vi.basePath, vi.perm); err != nil {
		return nil, fmt.Errorf("failed to create dir %v: %v", vi.basePath, err)
	}

	defer func() {
		if err != nil {
			os.RemoveAll(vi.basePath)
		}
	}()

	if err = os.Chown(vi.basePath, int(vi.uid), int(vi.gid)); err != nil {
		return nil, fmt.Errorf("failed to set ownership for dir %v: %v", vi.basePath, err)
	}

	if _, err := os.Stat(vi.contPath); err == nil {
		if err = mgr.syncInBaseVol(id, vi, skipImgCopy); err != nil {
			return nil, fmt.Errorf("failed to sync-in base volume %v: %v", vi.basePath, err)
		}
	}

	mnt := []specs.Mount{
		{
			Source:      vi.basePath,
			Destination: mountpoint,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	logrus.Debugf("Created base vol for container %v", id)

	return mnt, nil
}

func (mgr *dockerVolMgr) destroyBaseVol(id string, vi *volInfo) error {

	if err := os.RemoveAll(vi.basePath); err != nil {
		return fmt.Errorf("failed to destroy base vol at %s: %s", vi.basePath, err)
	}

	logrus.Debugf("Destroyed base vol for container %v", id)

	return nil
}

// Copies the container's inner /var/lib/docker dir (if any) to the given base vol.
// If skipImgCopy is true, skips copying any inner images under the /var/lib/docker dir.
func (mgr *dockerVolMgr) syncInBaseVol(id string, vi *volInfo, skipImgCopy bool) error {
	var exclude string

	if skipImgCopy {
		exclude = "/" + dockerImgDir + "/[0-9a-z]*[0-9a-z]/diff"
	}

	// Note: set 'deleteAtRx' to false during sync-in (copy everything)
	if err := rsyncVol(vi.contPath, vi.basePath, vi.uid, vi.gid, vi.shiftUids, exclude, false); err != nil {
		return fmt.Errorf("volume sync-in for %v failed: %v", id, err)
	}

	logrus.Debugf("Sync'd-in base vol for container %v", id)

	return nil
}

// Copies the base volume's contents to the container's /var/lib/docker dir (if any).
// If skipImgCopy is true, skips copying any inner images to the /var/lib/docker dir.
func (mgr *dockerVolMgr) syncOutBaseVol(id string, vi *volInfo, skipImgCopy bool) error {

	// contPath is the sync-out target; if it does not exist, create it (but only if we are
	// going to be copying anything to it).
	if _, err := os.Stat(vi.contPath); os.IsNotExist(err) {
		baseVolIsEmpty, err := dirIsEmpty(vi.basePath)
		if err != nil {
			return fmt.Errorf("error while checking if %s is empty: %s", vi.basePath, err)
		}
		if !baseVolIsEmpty {
			if err := os.MkdirAll(vi.contPath, vi.perm); err != nil {
				return fmt.Errorf("failed to create directory %s: %s", vi.contPath, err)
			}
		}
	}

	// if the sync-out target exists, perform the rsync
	if _, err := os.Stat(vi.contPath); err == nil {
		var exclude string

		if skipImgCopy {
			exclude = "/" + dockerImgDir + "/[0-9a-z]*[0-9a-z]/diff"
		}

		// Note: set 'deleteAtRx' to true during sync-out (delete files at receiver that are not in the source)
		if err := rsyncVol(vi.basePath, vi.contPath, 0, 0, vi.shiftUids, exclude, true); err != nil {
			return fmt.Errorf("failed ot sync-out base vol for container %v: %v", id, err)
		}
	}

	logrus.Debugf("Sync'd-out base vol for container %v", id)

	return nil
}

// Setup sys container inner docker image sharing using copy-on-write.
func (mgr *dockerVolMgr) setupImgSharing(id, imgID string, vi *volInfo) ([]specs.Mount, error) {
	var err error

	// Create the image volume for the container image; it holds a copy of the container's
	// inner docker images. This volume will be shared by all containers using the same
	// image. We only create the image volume if this is the first container for this
	// image.

	mgr.imgTableMu.Lock()
	defer mgr.imgTableMu.Unlock()

	imgVi, found := mgr.imgTable[imgID]
	if !found {
		imgVi, err = mgr.createImgVol(imgID, vi)
		if err != nil {
			return nil, err
		}
		mgr.imgTable[imgID] = imgVi
	}

	// Create the cow volume for this container; it holds the overlayfs mounts that back
	// the inner docker images for the container. There is one of these per container.
	cowMnt, err := mgr.createCowVol(id, imgVi, vi)
	if err != nil {
		return nil, err
	}

	imgVi.refCnt++

	return cowMnt, nil
}

// Teardown sys container inner docker image sharing.
func (mgr *dockerVolMgr) teardownImgSharing(id string, vi *volInfo) error {

	mgr.imgTableMu.Lock()
	defer mgr.imgTableMu.Unlock()

	imgVi, found := mgr.imgTable[vi.imgID]
	if !found {
		return fmt.Errorf("no image vol found for image %s", vi.imgID)
	}

	if err := mgr.destroyCowVol(id, vi, imgVi); err != nil {
		return err
	}

	imgVi.refCnt--

	// if last container for this image, destroy image vol
	if imgVi.refCnt == 0 {
		if err := mgr.destroyImgVol(vi.imgID, imgVi); err != nil {
			return err
		}
		delete(mgr.imgTable, vi.imgID)
	}

	return nil
}

// Creates an image volume for the given image
func (mgr *dockerVolMgr) createImgVol(imgID string, vi *volInfo) (*imgVolInfo, error) {
	var err error

	// creates an the image volume for the given container image
	imgVolPath := filepath.Join(mgr.imgVolDir, imgID)
	if err := os.Mkdir(imgVolPath, mgrPerm); err != nil {
		return nil, fmt.Errorf("failed to create dir %v: %v", imgVolPath, err)
	}

	defer func() {
		if err != nil {
			os.RemoveAll(imgVolPath)
		}
	}()

	// Copy the container's inner docker images (/var/lib/docker/overlay2) to the image
	// volume. To speed up things, we launch a go routine to copy each inner docker image.

	contImgPath := filepath.Join(vi.contPath, dockerImgDir)

	images, err := ioutil.ReadDir(contImgPath)
	if err != nil {
		return nil, err
	}

	// deploy a go-routine to do the copy for each inner image
	var wg sync.WaitGroup
	errch := make(chan error, len(images))

	for _, img := range images {

		// skip the "l" subdir since it only contains links, not images.
		if img.Name() == "l" {
			continue
		}

		srcDir := filepath.Join(contImgPath, img.Name())
		dstDir := filepath.Join(imgVolPath, img.Name())
		exclude := ""

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Note: set 'deleteAtRx' to false during sync-in (copy everything)
			if err := rsyncVol(srcDir, dstDir, 0, 0, false, exclude, false); err != nil {
				errch <- fmt.Errorf("failed to sync in img vol (%s -> %s): %s", srcDir, dstDir, err)
			}
		}()
	}

	wg.Wait()

	select {
	case err = <-errch:
		return nil, err
	default:
	}

	imgVi := &imgVolInfo{
		volPath:     imgVolPath,
		contImgPath: contImgPath,
	}

	logrus.Debugf("Created image vol for image %v", imgID)

	return imgVi, nil
}

func (mgr *dockerVolMgr) destroyImgVol(imgID string, imgVi *imgVolInfo) error {

	if err := os.RemoveAll(imgVi.volPath); err != nil {
		return fmt.Errorf("failed to destroy image vol at %s: %s", imgVi.volPath, err)
	}

	logrus.Debugf("Destroyed image vol for image %v", imgID)

	return nil
}

// Creates the copy-on-write (COW) volume for the given container
func (mgr *dockerVolMgr) createCowVol(id string, imgVi *imgVolInfo, vi *volInfo) ([]specs.Mount, error) {

	// Create and populate a cow vol for a given container: for each image layer in the
	// associated image vol, create the following dir structure under the container's
	// cow vol:
	//
	// container-id/
	//   inner-image0/
	//     lower -> /soft/link/to/imgVol/imgID/inner-image0/diff
	//     merged
	//     upper
	//     work
	//   inner-image1/
	//     lower -> /soft/link/to/imgVol/imgID/inner-image1/diff
	//     merged
	//     upper
	//     work

	cowVol := filepath.Join(mgr.cowVolDir, id)
	if err := os.Mkdir(cowVol, mgrPerm); err != nil {
		return nil, fmt.Errorf("failed to create dir %v: %v", cowVol, err)
	}

	images, err := ioutil.ReadDir(imgVi.volPath)
	if err != nil {
		return nil, err
	}

	cowMnts := []specs.Mount{}
	mntch := make(chan specs.Mount, len(images))
	errch := make(chan error, len(images))

	var wg sync.WaitGroup
	for _, img := range images {
		wg.Add(1)
		go createCowVolOvfsMnt(img, vi, imgVi, cowVol, &wg, mntch, errch)
	}
	wg.Wait()

	select {
	case err = <-errch:
		os.RemoveAll(cowVol)
		return nil, err
	default:
		for range images {
			cowMnts = append(cowMnts, <-mntch)
		}
	}

	vi.cowPath = cowVol
	logrus.Debugf("Created cow vol for container %v", id)
	return cowMnts, nil
}

// Helper to create the ovfs mount dirs for a single inner image layer.
func createCowVolOvfsMnt(img os.FileInfo, vi *volInfo, imgVi *imgVolInfo, cowVol string, wg *sync.WaitGroup, mntch chan specs.Mount, errch chan error) {
	var lower, upper, merged, work string
	var err error

	defer wg.Done()

	imgPath := filepath.Join(imgVi.volPath, img.Name())
	ovfsPath := filepath.Join(cowVol, img.Name())
	mntPath := filepath.Join(dockerRoot, dockerImgDir, img.Name(), "diff")

	ovfsDirs := []string{"upper", "merged", "work"}

	// inner-image-X
	if err = os.Mkdir(ovfsPath, mgrPerm); err != nil {
		errch <- fmt.Errorf("failed to create dir %v: %v", ovfsPath, err)
		return
	}

	// inner-image-X subdirs
	for _, dir := range ovfsDirs {
		path := filepath.Join(ovfsPath, dir)
		if err = os.Mkdir(path, mgrPerm); err != nil {
			errch <- fmt.Errorf("failed to create dir %v: %v", path, err)
			return
		}
		switch dir {
		case "upper":
			upper = path
		case "merged":
			merged = path
		case "work":
			work = path
		}
	}

	// "lower" dir soft-link
	lower = filepath.Join(ovfsPath, "lower")
	imgDiff := filepath.Join(imgPath, "diff")

	if err = os.Symlink(imgDiff, lower); err != nil {
		errch <- fmt.Errorf("failed to create symlink from %v -> %v: %v", lower, imgDiff, err)
		return
	}

	// overlayfs mount (metacopy enabled to prevent full copy-up on chown)
	opts := fmt.Sprintf("metacopy=on,lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	if err = syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		errch <- fmt.Errorf("error mounting overlayfs on %s: %v", merged, err)
		return
	}

	defer func() {
		if err != nil {
			syscall.Unmount(merged, unix.MNT_DETACH)
		}
	}()

	// chown: "merged" dir ownership must match container uid(gid)
	err = filepath.Walk(merged, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("path walk failed for %s: %s", path, err)
		}
		if err2 := os.Chown(path, int(vi.uid), int(vi.gid)); err2 != nil {
			// ignore errors on symlinks (those may not resolve to valid targets until mounted in the container)
			if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
				return fmt.Errorf("failed to set ownership for %s: %s", path, err2)
			}
		}
		return nil
	})
	if err != nil {
		errch <- err
		return
	}

	mnt := specs.Mount{
		Source:      merged,
		Destination: mntPath,
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	}

	mntch <- mnt
}

func (mgr *dockerVolMgr) destroyCowVol(id string, vi *volInfo, imgVi *imgVolInfo) error {

	// remove cow-vol overlayfs mounts (with a go-routine to unmount each)
	images, err := ioutil.ReadDir(imgVi.volPath)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	errch := make(chan error, len(images))

	for _, img := range images {
		mntPath := filepath.Join(vi.cowPath, img.Name(), "merged")

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := syscall.Unmount(mntPath, unix.MNT_DETACH); err != nil {
				logrus.Debugf("failed to unmount ovfs from %s: %s", mntPath, err)
				errch <- err
			}
			logrus.Debugf("umounted ovfs from %s", mntPath)
		}()
	}

	wg.Wait()

	select {
	case err = <-errch:
		return err
	default:
	}

	if err := os.RemoveAll(vi.cowPath); err != nil {
		return fmt.Errorf("failed to destroy dir %v: %v", vi.cowPath, err)
	}

	logrus.Debugf("Destroyed cow vol for container %v", id)
	return nil
}

func (mgr *dockerVolMgr) syncOutCowVol(id string, vi *volInfo) error {

	// For each inner image in the container's cow-vol, copy:
	// inner-image/upper -> container-rootfs/var/lib/docker/overlay2/inner-image/diff
	// Use a go-routine for each inner image.

	images, err := ioutil.ReadDir(vi.cowPath)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	errch := make(chan error, len(images))

	for _, img := range images {
		srcDir := filepath.Join(vi.cowPath, img.Name(), "upper")
		dstDir := filepath.Join(vi.contPath, dockerImgDir, img.Name(), "diff")
		exclude := ""

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Note: since we are copying the diffs only, the rsyncVol 'deleteAtRx' must be false.
			if err := rsyncVol(srcDir, dstDir, 0, 0, vi.shiftUids, exclude, false); err != nil {
				errch <- fmt.Errorf("failed to sync out cow vol (%s -> %s): %s", srcDir, dstDir, err)
			}
		}()
	}

	wg.Wait()

	select {
	case err = <-errch:
		return err
	default:
	}

	logrus.Debugf("Sync'd-out cow vol for container %v", id)
	return nil
}
