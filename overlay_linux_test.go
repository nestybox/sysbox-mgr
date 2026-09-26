package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	"github.com/nestybox/sysbox-libs/idShiftUtils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestRelativeOverlayUpperLayerOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test only runs as root")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		t.Fatal(err)
	}
	if caps[0].Effective&(1<<unix.CAP_SYS_ADMIN) == 0 {
		t.Skip("This test requires CAP_SYS_ADMIN")
	}

	base := t.TempDir()
	upper := filepath.Join(base, "container", "diff")
	rootfs := filepath.Join(base, "container", "merged")
	for _, dir := range []string{"l/layer-one", "container/diff", "container/work", "container/merged"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Only the mounting child changes cwd; mgr must resolve paths from elsewhere.
	cmd := exec.Command("mount", "-t", "overlay", "overlay", "-o",
		"lowerdir=l/layer-one,upperdir=container/diff,workdir=container/work", rootfs)
	cmd.Dir = base
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mount: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(rootfs, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})

	const id = "relative-overlay"
	const hostID = 231072
	mappings := []specs.LinuxIDMapping{{ContainerID: 0, HostID: hostID, Size: 65536}}
	mgr := &SysboxMgr{
		contTable: map[string]containerInfo{
			id: {
				rootfs:       rootfs,
				rootfsOnOvfs: true,
				uidMappings:  mappings,
				gidMappings:  mappings,
			},
		},
	}
	// Model runc's update after it has shifted the upperdir for an ID-mapped rootfs.
	if err := mgr.update(&ipcLib.UpdateInfo{Id: id, RootfsUidShiftType: idShiftUtils.IDMappedMount}); err != nil {
		t.Fatal(err)
	}
	if got := mgr.contTable[id].rootfsOvfsUpper; got != upper {
		t.Fatalf("saved upperdir = %q, want %q", got, upper)
	}

	marker := filepath.Join(upper, "marker")
	if err := os.WriteFile(marker, []byte("persisted"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{upper, marker} {
		if err := os.Chown(path, hostID, hostID); err != nil {
			t.Fatal(err)
		}
	}
	checkOwner := func(want uint32) {
		t.Helper()
		var stat unix.Stat_t
		if err := unix.Stat(marker, &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Uid != want || stat.Gid != want {
			t.Fatalf("marker owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, want, want)
		}
	}
	if err := mgr.pause(id); err != nil {
		t.Fatal(err)
	}
	checkOwner(0)
	if err := mgr.resume(id); err != nil {
		t.Fatal(err)
	}
	checkOwner(hostID)

	t.Run("invalid base is propagated", func(t *testing.T) {
		misplaced := filepath.Join(base, "nested", "container", "merged")
		if err := os.MkdirAll(misplaced, 0755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(rootfs, misplaced, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := unix.Unmount(misplaced, unix.MNT_DETACH); err != nil {
				t.Error(err)
			}
		})
		info := mgr.contTable[id]
		info.rootfs = misplaced
		mgr.contTable[id] = info
		err := mgr.update(&ipcLib.UpdateInfo{Id: id, RootfsUidShiftType: idShiftUtils.IDMappedMount})
		if err == nil || !strings.Contains(err.Error(), "cannot resolve relative overlay paths") {
			t.Fatalf("update() error = %v, want an invalid-base error", err)
		}
	})
}
