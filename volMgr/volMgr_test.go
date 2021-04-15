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

package volMgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	utils "github.com/nestybox/sysbox-libs/utils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type testFile struct {
	name string
	uid  uint32
	gid  uint32
}

func init() {
	// turn off info & debug logging for unit tests
	logrus.SetLevel(logrus.ErrorLevel)
}

func setupTest() (string, string, error) {
	hostDir, err := ioutil.TempDir("", "volMgrTest-host")
	if err != nil {
		return "", "", err
	}

	rootfs, err := ioutil.TempDir("", "volMgrTest-rootfs")
	if err != nil {
		return "", "", err
	}

	return hostDir, rootfs, nil
}

func cleanupTest(hostDir, rootfs string) {
	os.RemoveAll(hostDir)
	os.RemoveAll(rootfs)
}

func populateDir(base string, uid, gid uint32, files []testFile) error {
	data := []byte("some data")

	// create the files in the directory
	for _, file := range files {

		dir := filepath.Dir(file.name)
		path := filepath.Join(base, dir)
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("failed to create dir %v: %v", path, err)
		}

		path = filepath.Join(base, file.name)

		if err := ioutil.WriteFile(path, data, 0700); err != nil {
			return fmt.Errorf("failed to create file %v: %v", path, err)
		}
	}

	// chown the files
	err := filepath.Walk(base, func(path string, fi os.FileInfo, err error) error {
		if err == nil {

			// chown all dirs & files to the given uid & gid by default
			if err := os.Chown(path, int(uid), int(gid)); err != nil {
				return fmt.Errorf("chown on %s failed: %s", path, err)
			}

			// for the given files, chown to the file-specific uid & gid
			for _, file := range files {
				if strings.Contains(path, file.name) {
					if err := os.Chown(path, int(file.uid), int(file.gid)); err != nil {
						return fmt.Errorf("chown on %s failed: %s", path, err)
					}
				}
			}
		}
		return err
	})

	if err != nil {
		return fmt.Errorf("failed to chown files: %s", err)
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

	if !utils.StringSliceEqual(srcPaths, destPaths) {
		return fmt.Errorf("mismatch between %v and %v", srcPaths, destPaths)
	}

	return nil
}

func testCreateVolWork(id, hostDir, rootfs, mountpoint string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	want := []specs.Mount{
		{
			Source:      filepath.Join(hostDir, id),
			Destination: mountpoint,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	mgr, err := New("testVolMgr", hostDir, true)
	if err != nil {
		return nil, fmt.Errorf("New(%v) returned %v", hostDir, err)
	}

	got, err := mgr.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids, 0700)
	if err != nil {
		return nil, fmt.Errorf("CreateVol() returned %v", err)
	}

	// check that the volMgr volTable entry got created
	vmgr := mgr.(*vmgr)
	if _, found := vmgr.volTable[id]; !found {
		return nil, fmt.Errorf("CreateVol() did not create entry in volTable")
	}

	// check that CreateVol returned the expected mount
	if !utils.MountSliceEqual(got, want) {
		return nil, fmt.Errorf("CreateVol(%v, %v, %v, %v, %v, 0700) returned %v, want %v", id, rootfs, mountpoint, uid, gid, got, want)
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
	mountpoint := "/var/lib/kubelet"
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

	mgr, err := New("testVolMgr", hostDir, true)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/kubelet"
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	_, err = mgr.CreateVol(id, rootfs, mountpoint, uid, gid, false, 0700)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// check that the volMgr volTable entry got created
	vmgr := mgr.(*vmgr)
	if _, found := vmgr.volTable[id]; !found {
		t.Errorf("CreateVol() did not create entry in volTable")
	}

	if err := mgr.DestroyVol(id); err != nil {
		t.Errorf("DestroyVol(%v) returned %v", id, err)
	}

	// check that the volMgr volTable entry got removed
	if _, found := vmgr.volTable[id]; found {
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
		t.Skip("This test only runs as root")
	}

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create a fake container rootfs and populate its "/var/lib/kubelet"
	id := "test-cont"
	mountpoint := "/var/lib/kubelet"
	uid = 231072
	gid = 231072

	rootfsUidOffset := uint32(0)
	rootfsGidOffset := uint32(0)

	if !shiftUids {
		rootfsUidOffset = uid
		rootfsGidOffset = gid
	}

	files := []testFile{
		{
			name: "testdir1/a/b/c/d/file0",
			uid:  rootfsUidOffset + 0,
			gid:  rootfsGidOffset + 0,
		},
		{
			name: "testdir1/a/file1",
			uid:  rootfsUidOffset + 1000,
			gid:  rootfsGidOffset + 1000,
		},
		{
			name: "testdir3/a/b/file2",
			uid:  rootfsUidOffset + 100,
			gid:  rootfsGidOffset + 100,
		},
	}

	mountPath := filepath.Join(rootfs, mountpoint)

	if err := populateDir(mountPath, rootfsUidOffset, rootfsGidOffset, files); err != nil {
		t.Errorf("failed to populate rootfs mountpoint: %v", err)
	}

	// create the volume mgr; this triggers the sync-in automatically.
	mgr, err := New("testVolMgr", hostDir, true)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	_, err = mgr.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids, 0700)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// verify the sync-in worked
	volPath := filepath.Join(hostDir, id)

	if err := compareDirs(volPath, mountPath); err != nil {
		t.Errorf("directory comparison between %v and %v failed: %v", volPath, mountPath, err)
	}

	// verify the sync-in shifted the file uid and gid correctly
	err = filepath.Walk(volPath, func(path string, fi os.FileInfo, err error) error {
		wantUid := uint32(uid)
		wantGid := uint32(gid)

		for _, f := range files {
			if filepath.Base(f.name) == filepath.Base(path) {
				if shiftUids {
					// sync-in shifts uids by adding the container's root uid to them
					wantUid = uid + f.uid
					wantGid = gid + f.gid
				} else {
					wantUid = f.uid
					wantGid = f.gid
				}
			}
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
		t.Skip("This test only runs as root")
	}

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create the volume mgr
	mgr, err := New("testVolMgr", hostDir, true)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/kubelet"
	uid = 231072
	gid = 231072

	_, err = mgr.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids, 0700)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// Add some files to the volume mgr
	volPath := filepath.Join(hostDir, id)

	files := []testFile{
		{
			name: "testdir1/a/b/c/d/file0",
			uid:  uid + 0,
			gid:  gid + 0,
		},
		{
			name: "testdir1/a/file1",
			uid:  uid + 1000,
			gid:  gid + 1000,
		},
		{
			name: "testdir3/a/b/file2",
			uid:  uid + 100,
			gid:  gid + 100,
		},
	}

	if err := populateDir(volPath, uid, gid, files); err != nil {
		t.Errorf("failed to populate vol at path %s: %s", volPath, err)
	}

	// sync-out the vol to the rootfs; this will create the target dir automatically
	if err := mgr.SyncOut(id); err != nil {
		t.Errorf("sync-out failed: %s", err)
	}

	// verify that the sync-out worked
	mountPath := filepath.Join(rootfs, mountpoint)

	if err := compareDirs(volPath, mountPath); err != nil {
		t.Errorf("directory comparison between %v and %v failed: %v", volPath, mountPath, err)
	}

	err = filepath.Walk(mountPath, func(path string, fi os.FileInfo, err error) error {
		var wantUid, wantGid uint32

		if shiftUids {
			wantUid = 0
			wantGid = 0
		} else {
			wantUid = uid
			wantGid = gid
		}

		for _, f := range files {
			if filepath.Base(f.name) == filepath.Base(path) {
				if shiftUids {
					// sync-out shifts uids by subtracting the container's root uid from them
					wantUid = f.uid - uid
					wantGid = f.gid - gid
				} else {
					wantUid = f.uid
					wantGid = f.gid
				}
			}
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

	// create the volMgr
	mgr, err := New("testVolMgr", hostDir, true)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/kubelet"
	uid := uint32(231072)
	gid := uint32(231072)

	_, err = mgr.CreateVol(id, rootfs, mountpoint, uid, gid, false, 0700)
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

	// create the volMgr
	mgr, err := New("testVolMgr", hostDir, true)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/kubelet"
	uid := uint32(231072)
	gid := uint32(231072)

	_, err = mgr.CreateVol(id, rootfs, mountpoint, uid, gid, false, 0700)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	// this sync-out should be a "no-op" since the volume is empty
	if err := mgr.SyncOut(id); err != nil {
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
