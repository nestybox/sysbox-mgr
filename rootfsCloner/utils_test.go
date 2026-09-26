//go:build linux
// +build linux

package rootfsCloner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nestybox/sysbox-libs/mount"
	"golang.org/x/sys/unix"
)

func TestSetupBottomMountInvalidBase(t *testing.T) {
	base := t.TempDir()
	ci := &cloneInfo{
		origRootfsMntInfo: &mount.Info{
			Mountpoint: filepath.Join(base, "container", "merged"),
			VfsOpts:    "rw,lowerdir=l/missing-layer,upperdir=container/diff,workdir=container/work",
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	err = setupBottomMount(ci)
	want := "cannot resolve relative overlay paths: " + filepath.Join(base, "l", "missing-layer")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("setupBottomMount() error = %v, want %q", err, want)
	}
	gotCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if gotCwd != cwd {
		t.Fatalf("setupBottomMount() changed cwd to %q, want %q", gotCwd, cwd)
	}
}

func TestSetupBottomMountPreservesCwdOnMountFailure(t *testing.T) {
	base := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Error(err)
		}
	})

	for _, dir := range []string{"l/layer-one", "clone/diff", "clone/work"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	ci := &cloneInfo{
		origRootfsMntInfo: &mount.Info{
			Mountpoint: filepath.Join(base, "container", "merged"),
			VfsOpts:    "rw,lowerdir=l/layer-one,upperdir=container/diff,workdir=container/work",
		},
		ovfsMount: ovfsMntInfo{
			// Leave the target absent so mounting fails even with CAP_SYS_ADMIN.
			mergedDir: filepath.Join(base, "clone", "missing-merged"),
			diffDir:   filepath.Join(base, "clone", "diff"),
			workDir:   filepath.Join(base, "clone", "work"),
		},
	}
	err = setupBottomMount(ci)
	if err == nil || !strings.Contains(err.Error(), "failed to mount overlayfs on ") {
		t.Fatalf("setupBottomMount() error = %v, want a mount error", err)
	}
	gotCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if gotCwd != cwd {
		t.Fatalf("setupBottomMount() left cwd at %q, want %q", gotCwd, cwd)
	}
}

func TestSetupBottomMountConcurrent(t *testing.T) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		t.Fatal(err)
	}
	if caps[0].Effective&(1<<unix.CAP_SYS_ADMIN) == 0 {
		t.Skip("This test requires CAP_SYS_ADMIN")
	}

	testDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Error(err)
		}
	})

	const workers = 32
	clones := make([]*cloneInfo, workers)
	start := make(chan struct{})
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		marker := fmt.Sprint(i)
		base := filepath.Join(testDir, marker)
		for _, dir := range []string{"l/layer-one", "clone/diff", "clone/work", "clone/merged"} {
			if err := os.MkdirAll(filepath.Join(base, dir), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(base, "l", "layer-one", "marker"), []byte(marker), 0644); err != nil {
			t.Fatal(err)
		}
		ci := &cloneInfo{
			origRootfsMntInfo: &mount.Info{
				Mountpoint: filepath.Join(base, "container", "merged"),
				VfsOpts:    "rw,lowerdir=l/layer-one,upperdir=container/diff,workdir=container/work",
			},
			ovfsMount: ovfsMntInfo{
				mergedDir: filepath.Join(base, "clone", "merged"),
				diffDir:   filepath.Join(base, "clone", "diff"),
				workDir:   filepath.Join(base, "clone", "work"),
			},
		}
		clones[i] = ci
		t.Cleanup(func() {
			// Also clean up a mount if its propagation setup failed.
			if err := unix.Unmount(ci.ovfsMount.mergedDir, unix.MNT_DETACH); err != nil && err != unix.EINVAL {
				t.Error(err)
			}
		})
	}
	for i, ci := range clones {
		marker := fmt.Sprint(i)
		go func() {
			<-start
			if err := setupBottomMount(ci); err != nil {
				results <- fmt.Errorf("clone %s: %w", marker, err)
				return
			}
			data, err := os.ReadFile(filepath.Join(ci.ovfsMount.mergedDir, "marker"))
			if err == nil && string(data) != marker {
				err = fmt.Errorf("clone %s mounted layer %q", marker, data)
			}
			results <- err
		}()
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
		// This goroutine must retain its cwd while other clones are mounting.
		if got, err := os.Getwd(); err != nil {
			t.Error(err)
		} else if got != cwd {
			t.Errorf("cwd = %q during concurrent mounts, want %q", got, cwd)
		}
	}
}
