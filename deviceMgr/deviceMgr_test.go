package deviceMgr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nestybox/sysbox-mgr/deviceMgr/gpu/nvidia"
	"github.com/nestybox/sysbox-mgr/deviceMgr/root"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestRootDevicerPassthrough verifies that the root devicer does not match any
// device path: sysbox-runc treats the "/" prefix as a sentinel meaning "not a
// supported device", so the original oci-spec device must pass through the
// device manager completely untouched.
func TestRootDevicerPassthrough(t *testing.T) {
	d := root.NewRootDevicer()
	dev := specs.LinuxDevice{Type: "c", Path: "/dev/not-a-device", Major: 1, Minor: 3}

	out, err := d.Discover(&dev)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if out != nil {
		t.Errorf("root devicer must not discover anything, got %+v", out)
	}
	if d.CreateByDefault() {
		t.Errorf("root devicer must not create by default")
	}
}

// TestNvidiaDiscoverReconciliation checks the nvidia devicer's path
// reconciliation: a container device path (as written by DRA/CDI into the runc
// spec) must resolve to an existing host node across the known NVIDIA driver
// roots, including /dev for MIG caps (e.g. /dev/nvidia-caps).
//
// This test is host-aware: it only asserts on paths that actually exist on the
// host, so it can run both on GPU-Operator nodes and on plain systems.
func TestNvidiaDiscoverReconciliation(t *testing.T) {
	devicer := nvidia.NewNvidiaDevicer()

	// Typical DRA/CDI deviceNodes for a MIG slice.
	candidates := []string{
		"/dev/nvidia0",
		"/dev/nvidia-caps/nvidia-cap102",
		"/dev/nvidia-caps/nvidia-cap103",
		"/dev/nvidia-modeset",
		"/dev/nvidia-uvm",
		"/dev/nvidia-uvm-tools",
		"/dev/nvidiactl",
	}

	// Both the direct /dev path and the GPU-Operator mirror under
	// /run/nvidia/driver are valid host sources for the same container path.
	driverRoots := []string{"/", "/run/nvidia/driver"}

	for _, path := range candidates {
		dev, err := devicer.Discover(&specs.LinuxDevice{Type: "c", Path: path})
		if err != nil {
			t.Errorf("Discover(%s) returned error: %v", path, err)
			continue
		}

		// If none of the host roots contain this device, the devicer must
		// return nil (meaning "cannot discover"); sysbox-runc then surfaces a
		// clear error rather than a raw ENOENT.
		hostResolved := false
		for _, d := range driverRoots {
			if _, err := os.Stat(filepath.Join(d, path)); err == nil {
				hostResolved = true
				break
			}
		}

		if !hostResolved {
			if dev != nil {
				t.Errorf("Discover(%s) returned %v but no host node exists", path, dev.Path)
			}
			continue
		}

		if dev == nil {
			t.Fatalf("Discover(%s) returned nil despite host node existing", path)
		}
		// Resolved path must be absolute and exist.
		if !filepath.IsAbs(dev.Path) {
			t.Errorf("Discover(%s) returned non-absolute path %q", path, dev.Path)
		}
		if _, err := os.Stat(dev.Path); err != nil {
			t.Errorf("Discover(%s) returned %q which does not exist: %v", path, dev.Path, err)
		}
	}
}

// TestSetupDevicesRoundTrip exercises the full DeviceMgr pipeline for a device
// that the manager resolves and creates through a temp hostDir, then tears it
// down. This is guarded on /dev/net/tun existing since the net devicer is
// CreateByDefault and runs during every SetupDevices call.
func TestSetupDevicesRoundTrip(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not present on host; skipping full SetupDevices test")
	}
	// Creating device nodes requires root (CAP_MKNOD); skip when unprivileged.
	if os.Geteuid() != 0 {
		t.Skip("device-node creation requires root; skipping full SetupDevices test")
	}

	hostDir := t.TempDir()

	m := New(hostDir)
	if m == nil {
		t.Fatalf("failed to create device manager")
	}

	// A device representing a resolved GPU node: type char, arbitrary numbers.
	// Its path must fall under a registered devicer prefix (/dev/nvidia) so it
	// gets discovered; the nvidia devicer resolves it against the host.
	dev := specs.LinuxDevice{
		Type:     "c",
		Path:     "/dev/nvidia0",
		Major:    195,
		Minor:    0,
		FileMode: &modeChar,
	}

	resolved, err := m.SetupDevices("cid-test", 0, 0, []specs.LinuxDevice{dev})
	if err != nil {
		t.Fatalf("SetupDevices returned error: %v", err)
	}

	// Setups the device node in the host dir if the device was created.
	if len(resolved) == 0 {
		t.Fatalf("SetupDevices returned no devices")
	}

	mounts := m.DeviceMounts("cid-test")
	if len(mounts) == 0 {
		t.Fatalf("expected at least one device mount")
	}

	if err := m.RemoveDevices("cid-test"); err != nil {
		t.Fatalf("RemoveDevices returned error: %v", err)
	}
}

var modeChar = os.ModeCharDevice
