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
)

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

func equalMount(a, b specs.Mount) bool {
	if a.Source != b.Source ||
		a.Destination != b.Destination ||
		a.Type != b.Type ||
		!equalStrings(a.Options, b.Options) {
		return false
	}

	return true
}

func equalMounts(a, b []specs.Mount) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalMount(a[i], b[i]) {
			return false
		}
	}
	return true
}

func testCreateVolWork(id, hostDir, rootfs, mountpoint string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	got := []specs.Mount{}

	want := []specs.Mount{
		{
			Source:      filepath.Join(hostDir, id),
			Destination: mountpoint,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	ds, err := New(hostDir)
	if err != nil {
		return got, fmt.Errorf("New(%v) returned %v", hostDir, err)
	}

	got, err = ds.CreateVol(id, rootfs, mountpoint, uid, gid, shiftUids)
	if err != nil {
		return got, fmt.Errorf("CreateVol() returned %v", err)
	}

	if !equalMounts(got, want) {
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

	ds, err := New(hostDir)
	if err != nil {
		t.Errorf("New(%v) returned %v", hostDir, err)
	}

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	_, err = ds.CreateVol(id, rootfs, mountpoint, uid, gid, false)
	if err != nil {
		t.Errorf("CreateVol() returned %v", err)
	}

	if err := ds.DestroyVol(id); err != nil {
		t.Errorf("DestroyVol(%v) returned %v", id, err)
	}

	// Verify the volume was indeed destroyed
	vol := filepath.Join(hostDir, id)
	if _, err := os.Stat(vol); err != nil {
		if !os.IsNotExist(err) {
			t.Errorf("DestroyVol(%v) failed: %v", id, err)
		}
	}

}

func TestVolCopyUp(t *testing.T) {

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	id := "test-cont"
	mountpoint := "/var/lib/docker"
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	files := []string{"testdir1/a/b/file0", "testdir2/c/d/file1", "testdir3/e/f/g/file2"}
	baseDir := filepath.Join(rootfs, mountpoint)
	if err := populateDir(baseDir, files); err != nil {
		t.Errorf("failed to populate rootfs mountpoint: %v", err)
	}

	if _, err := testCreateVolWork(id, hostDir, rootfs, mountpoint, uid, gid, false); err != nil {
		t.Errorf(err.Error())
	}

	src := filepath.Join(rootfs, mountpoint)
	dest := filepath.Join(hostDir, id)
	if err := compareDirs(src, dest); err != nil {
		t.Errorf("directory comparison between %v and %v failed: %v", src, dest, err)
	}
}

func TestVolOwnership(t *testing.T) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	if uid != 0 && gid != 0 {
		t.Skip("This test only runs as root, as it calls os.Chown()")
	}

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	id := "test-cont"
	mountpoint := "/var/lib/docker"

	mounts, err := testCreateVolWork(id, hostDir, rootfs, mountpoint, 1000, 1000, false)
	if err != nil {
		t.Errorf(err.Error())
	}

	// Check that the created volume has correct ownership
	vol := mounts[0].Source
	fi, err := os.Stat(vol)
	if err != nil {
		t.Errorf("os.Stat(%v) returned %v", vol, err)
	}
	stat := fi.Sys().(*syscall.Stat_t)
	if stat.Uid != 1000 || stat.Gid != 1000 {
		t.Errorf("uid:gid mismatch on volume %v: want %v:%v, got %v:%v", vol, 1000, 1000, stat.Uid, stat.Gid)
	}

}

func testUidShift(t *testing.T, shiftUids bool) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	if uid != 0 && gid != 0 {
		t.Skip("This test only runs as root, as it calls os.Chown()")
	}

	hostDir, rootfs, err := setupTest()
	if err != nil {
		t.Errorf("failed to setup test: %v", err)
	}
	defer cleanupTest(hostDir, rootfs)

	// create a fake cont rootfs with contents in "/var/lib/docker"
	id := "test-cont"
	mountpoint := "/var/lib/docker"

	files := []string{"testdir1/a/b/c/d/file0", "testdir1/a/file1", "testdir3/a/b/file2"}
	baseDir := filepath.Join(rootfs, mountpoint)
	if err := populateDir(baseDir, files); err != nil {
		t.Errorf("failed to populate rootfs mountpoint: %v", err)
	}

	// set the ownerships on all files under "/var/lib/docker" to root:root
	err = filepath.Walk(baseDir, func(path string, fi os.FileInfo, err error) error {
		if err == nil {
			if err := os.Chown(path, 0, 0); err != nil {
				return err
			}
		}
		return err
	})

	// create volume with 'shiftUids' set to true
	uid = 231072
	gid = 231072
	_, err = testCreateVolWork(id, hostDir, rootfs, mountpoint, uid, gid, shiftUids)
	if err != nil {
		t.Errorf(err.Error())
	}

	// verify that ownership of the volume and it's contents is set correctly
	vol := filepath.Join(hostDir, id)
	err = filepath.Walk(vol, func(path string, fi os.FileInfo, err error) error {
		var (
			wantUid uint32
			wantGid uint32
		)

		// only the contents of the volume are subject to uid shifting; the volume itself
		// always has the uid given to CreateVol()
		if path == vol {
			wantUid = 231072
			wantGid = 231072
		} else if shiftUids {
			wantUid = uid
			wantGid = gid
		} else {
			wantUid = 0
			wantGid = 0
		}

		if err == nil {
			stat := fi.Sys().(*syscall.Stat_t)
			if stat.Uid != wantUid || stat.Gid != wantGid {
				t.Errorf("uid:gid mismatch on volume path %v: want %v:%v, got %v:%v",
					path, wantUid, wantGid, stat.Uid, stat.Gid)
			}
		}
		return err
	})
}

func TestUidShift(t *testing.T) {
	testUidShift(t, true)
}

func TestNoUidShift(t *testing.T) {
	testUidShift(t, false)
}
