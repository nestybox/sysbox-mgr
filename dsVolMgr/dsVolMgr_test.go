//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package dsVolMgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

func init() {
	// turn off info & debug logging for unit tests
	logrus.SetLevel(logrus.ErrorLevel)
}

func setupTest() (string, string, error) {
	checkUnsupportedFs = false

	hostDir, err := ioutil.TempDir("", "dsMountMgrTest-docker")
	if err != nil {
		return "", "", err
	}

	rootfs, err := ioutil.TempDir("", "dsMountMgrTest-rootfs")
	if err != nil {
		return "", "", err
	}

	return hostDir, rootfs, nil
}

func cleanupTest(hostDir, rootfs string) {
	os.RemoveAll(hostDir)
	os.RemoveAll(rootfs)
}

func populateDir(base string, files []string) error {
	data := []byte("some data")

	for _, file := range files {
		dir := filepath.Dir(file)
		path := filepath.Join(base, dir)
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("failed to create dir %v: %v", path, err)
		}

		path = filepath.Join(base, file)
		if err := ioutil.WriteFile(path, data, 0700); err != nil {
			return fmt.Errorf("failed to create file %v: %v", path, err)
		}
	}

	return nil
}

func compareDirs(src, dest string) error {
	var err error

	srcPaths := []string{}
	err = filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err == nil {
			path = path[len(src):]
			srcPaths = append(srcPaths, path)
		}
		return err
	})

	if err != nil {
		return fmt.Errorf("failed walking path %v: %v", src, err)
	}

	destPaths := []string{}
	err = filepath.Walk(dest, func(path string, fi os.FileInfo, err error) error {
		if err == nil {
			path = path[len(dest):]
			destPaths = append(destPaths, path)
		}
		return err
	})

	if err != nil {
		return fmt.Errorf("failed walking path %v: %v", dest, err)
	}

	if !equalStrings(srcPaths, destPaths) {
		return fmt.Errorf("mismatch between %v and %v", srcPaths, destPaths)
	}

	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalMount(a, b *specs.Mount) bool {
	if a.Source != b.Source ||
		a.Destination != b.Destination ||
		a.Type != b.Type ||
		!equalStrings(a.Options, b.Options) {
		return false
	}

	return true
}

func testCreateVolWork(id, hostDir, rootfs, mountpoint string, uid, gid uint32, shiftUids bool) (*specs.Mount, error) {
	want := &specs.Mount{
		Source:      filepath.Join(hostDir, id),
		Destination: mountpoint,
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	}

	dsm, err := New(hostDir)
	if err != nil {
		return nil, fmt.Errorf("New(%v) returned %v", hostDir, err)
	}

	got, err := dsm.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids)
	if err != nil {
		return got, fmt.Errorf("CreateVol() returned %v", err)
	}

	// check that the dsVolMgr volTable entry got created
	mgr := dsm.(*mgr)
	if _, found := mgr.volTable[id]; !found {
		return got, fmt.Errorf("CreateVol() did not create entry in volTable")
	}

	// check that CreateVol returned the expected mount
	if !equalMount(got, want) {
		return got, fmt.Errorf("CreateVol(%v, %v, %v, %v, %v) returned %v, want %v", id, rootfs, mountpoint, uid, gid, got, want)
	}

	return got, nil
}

func TestCreateVol(t *testing.T) {
	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	// create the volume and verify all is good
	if _, err := testCreateVolWork(id, hostDir, rootfs, mountpoint, uid, gid, false); err != nil {
		t.Errorf(err.Error())
	}
}

func TestDestroyVol(t *testing.T) {

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	dsm, err := New(hostDir)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	_, err = dsm.CreateVol(id, rootfs, mountpoint, uid, gid, false)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// check that the dsVolMgr volTable entry got created
	mgr := dsm.(*mgr)
	if _, found := mgr.volTable[id]; !found {
		t.Errorf("CreateVol() did not create entry in volTable")
	}

	if err := dsm.DestroyVol(id); err != nil {
		t.Errorf("DestroyVol(%v) returned %v", id, err)
	}

	// check that the dsVolMgr volTable entry got removed
	if _, found := mgr.volTable[id]; found {
		t.Errorf("CreateVol() did not destroy entry in volTable")
	}

	// Verify the volume was indeed destroyed
	vol := filepath.Join(hostDir, id)
	if _, err := os.Stat(vol); err != nil {
		if !os.IsNotExist(err) {
			t.Errorf("DestroyVol(%v) failed: %v", id, err)
		}
	}
}

func testSyncInWork(t *testing.T, shiftUids bool) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	if uid != 0 && gid != 0 {
		t.Skip("This test only runs as root, as it changes file ownerships")
	}

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create a fake container rootfs and populate its "/var/lib/docker"
	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid = 231072
	gid = 231072

	files := []string{"testdir1/a/b/c/d/file0", "testdir1/a/file1", "testdir3/a/b/file2"}
	mountPath := filepath.Join(rootfs, mountpoint)

	if err := populateDir(mountPath, files); err != nil {
		t.Errorf("failed to populate rootfs mountpoint: %v", err)
	}

	// set the ownerships on all files under "<rootfs>/var/lib/docker" to root:root
	err = filepath.Walk(mountPath, func(path string, fi os.FileInfo, err error) error {
		if err == nil {
			if err := os.Chown(path, 0, 0); err != nil {
				return fmt.Errorf("chown on %s failed: %s", path, err)
			}
		}
		return err
	})
	if err != nil {
		t.Errorf("set ownership failed: %s", err)
	}

	// create the docker-store volume; this triggers the sync-in automatically.
	dsm, err := New(hostDir)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	_, err = dsm.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// verify the sync-in worked
	volPath := filepath.Join(hostDir, id)

	if err := compareDirs(volPath, mountPath); err != nil {
		t.Errorf("directory comparison between %v and %v failed: %v", volPath, mountPath, err)
	}

	err = filepath.Walk(volPath, func(path string, fi os.FileInfo, err error) error {
		var (
			wantUid uint32
			wantGid uint32
		)

		if shiftUids {
			wantUid = uid
			wantGid = gid
		} else {
			wantUid = 0
			wantGid = 0
		}

		if err == nil {
			stat := fi.Sys().(*syscall.Stat_t)
			if stat.Uid != wantUid || stat.Gid != wantGid {
				return fmt.Errorf("uid:gid mismatch on volume path %v: want %v:%v, got %v:%v",
					path, wantUid, wantGid, stat.Uid, stat.Gid)
			}
		}
		return err
	})
	if err != nil {
		t.Errorf("ownership check failed: %s", err)
	}
}

func TestSyncIn(t *testing.T) {
	testSyncInWork(t, false)
}

func TestSyncInUidShift(t *testing.T) {
	testSyncInWork(t, true)
}

func testSyncOutWork(t *testing.T, shiftUids bool) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	if uid != 0 && gid != 0 {
		t.Skip("This test only runs as root, as it changes file ownerships")
	}

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create the docker-store volume
	dsm, err := New(hostDir)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid = 231072
	gid = 231072

	_, err = dsm.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// Add some files to the docker-store volume
	volPath := filepath.Join(hostDir, id)
	files := []string{"testdir1/a/b/c/d/file0", "testdir1/a/file1", "testdir3/a/b/file2"}
	if err := populateDir(volPath, files); err != nil {
		t.Errorf("failed to populate vol at path %s: %s", volPath, err)
	}

	// set the ownerships on all files in the docker-store vol to uid:gid
	err = filepath.Walk(volPath, func(path string, fi os.FileInfo, err error) error {
		if err == nil {
			if err := os.Chown(path, int(uid), int(gid)); err != nil {
				return fmt.Errorf("chown on %s failed: %s", path, err)
			}
		}
		return err
	})
	if err != nil {
		t.Errorf("failed to change ownership on %s: %s", volPath, err)
	}

	// sync-out the docker-store vol to the rootfs; this will create the target dir automatically
	if err := dsm.SyncOut(id); err != nil {
		t.Errorf("sync-out failed: %s", err)
	}

	// verify that the sync-out worked
	mountPath := filepath.Join(rootfs, mountpoint)

	if err := compareDirs(volPath, mountPath); err != nil {
		t.Errorf("directory comparison between %v and %v failed: %v", volPath, mountPath, err)
	}

	err = filepath.Walk(mountPath, func(path string, fi os.FileInfo, err error) error {
		var (
			wantUid uint32
			wantGid uint32
		)

		if shiftUids {
			wantUid = 0
			wantGid = 0
		} else {
			wantUid = uid
			wantGid = gid
		}

		if err == nil {
			stat := fi.Sys().(*syscall.Stat_t)
			if stat.Uid != wantUid || stat.Gid != wantGid {
				return fmt.Errorf("uid:gid mismatch on volume path %v: want %v:%v, got %v:%v",
					path, wantUid, wantGid, stat.Uid, stat.Gid)
			}
		}
		return err
	})
	if err != nil {
		t.Errorf("ownership check failed: %s", err)
	}
}

func TestSyncOut(t *testing.T) {
	testSyncOutWork(t, false)
}

func TestSyncOutUidShift(t *testing.T) {
	testSyncOutWork(t, true)
}

func TestSyncInSkip(t *testing.T) {
	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create the docker-store volume
	dsm, err := New(hostDir)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid := uint32(231072)
	gid := uint32(231072)

	_, err = dsm.CreateVol(id, rootfs, mountpoint, uid, gid, false)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// since the moutpoint was not populated, verify the sync-in was skipped
	volPath := filepath.Join(hostDir, id)
	empty, err := dirIsEmpty(volPath)
	if err != nil {
		t.Errorf("dirIsEmpty(%s) failed: %s", volPath, err)
	}
	if !empty {
		t.Errorf("%s is not empty as expected", volPath)
	}

}

func TestSyncOutSkip(t *testing.T) {

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create the docker-store volume
	dsm, err := New(hostDir)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid := uint32(231072)
	gid := uint32(231072)

	_, err = dsm.CreateVol(id, rootfs, mountpoint, uid, gid, false)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// this sync-out should be a "no-op" since the volume is empty
	if err := dsm.SyncOut(id); err != nil {
		t.Errorf("sync-out failed: %s", err)
	}

	// verify sync-out was indeed a no-op
	mountPath := filepath.Join(rootfs, mountpoint)
	_, err = os.Stat(mountPath)
	if err == nil {
		t.Errorf("mountPath at %s was created erroneously", mountPath)
	} else if !os.IsNotExist(err) {
		t.Errorf("stat(%s) failed: %v", mountPath, err)
	}
}
