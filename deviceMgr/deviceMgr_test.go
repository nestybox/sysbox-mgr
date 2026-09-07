package deviceMgr

import (
	"os"
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

	out, toCreate, err := d.Discover(&dev)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if out != nil {
		t.Errorf("root devicer must not discover anything, got %+v", out)
	}
	if len(toCreate) != 0 {
		t.Errorf("root devicer must not request any host device materialization, got %+v", toCreate)
	}
	if d.CreateByDefault() {
		t.Errorf("root devicer must not create by default")
	}
}

// TestNvidiaDiscoverMaterializesDevNodes verifies the R-a contract of the nvidia
// devicer: every nvidia device node whose container path is under /dev (GPU
// nodes and MIG capability nodes as injected by DRA/CDI) must be (1) reported as
// a node to materialize on the host via the toCreate list (so the deviceMgr
// mknods it under sysboxDevDir and bind-mounts it into the container through
// DeviceMounts), and (2) returned to sysbox-runc with an empty Path so that runc
// skips its own container-side node creation/binding (which previously failed
// with EACCES on the 0700 /dev/nvidia-caps dir). This is independent of whether
// the node happens to exist on the host.
func TestNvidiaDiscoverMaterializesDevNodes(t *testing.T) {
	devicer := nvidia.NewNvidiaDevicer()

	// Typical DRA/CDI deviceNodes for a MIG slice (GPU nodes + MIG caps).
	candidates := []string{
		"/dev/nvidia0",
		"/dev/nvidia-caps/nvidia-cap102",
		"/dev/nvidia-caps/nvidia-cap103",
		"/dev/nvidia-modeset",
		"/dev/nvidia-uvm",
		"/dev/nvidia-uvm-tools",
		"/dev/nvidiactl",
	}

	for _, path := range candidates {
		dev, toCreate, err := devicer.Discover(&specs.LinuxDevice{Type: "c", Path: path, Major: 195, Minor: 0, FileMode: &modeChar})
		if err != nil {
			t.Errorf("Discover(%s) returned error: %v", path, err)
			continue
		}

		// The discovered device must have its Path cleared so runc skips bind/mknod.
		if dev == nil {
			t.Errorf("Discover(%s) must return a discovered device", path)
			continue
		}
		if dev.Path != "" {
			t.Errorf("Discover(%s) must return a Path-cleared device for runc, got %q", path, dev.Path)
		}

		// Exactly one node must be materialized on the host, preserving the
		// container path so DeviceMounts can bind it at the right destination.
		if len(toCreate) != 1 {
			t.Errorf("Discover(%s) must request exactly one host device materialization, got %d", path, len(toCreate))
			continue
		}
		if toCreate[0].Path != path {
			t.Errorf("Discover(%s) materialized node path mismatch: got %q", path, toCreate[0].Path)
		}
		if toCreate[0].Major != 195 || toCreate[0].Minor != 0 {
			t.Errorf("Discover(%s) materialized node must preserve major/minor, got %d:%d", path, toCreate[0].Major, toCreate[0].Minor)
		}
	}
}

// TestSetupDevicesMaterializesNvidiaDevice verifies the full DeviceMgr pipeline:
// SetupDevices must mknod the nvidia /dev node under the hostDir, return a
// Path-cleared device to the caller (runc), and DeviceMounts must emit a bind
// mount whose source is the materialized node and whose destination is the
// container path.
func TestSetupDevicesMaterializesNvidiaDevice(t *testing.T) {
	// Creating device nodes requires root (CAP_MKNOD); skip when unprivileged.
	if os.Geteuid() != 0 {
		t.Skip("device-node creation requires root; skipping SetupDevices test")
	}

	hostDir := t.TempDir()

	m := New(hostDir)
	if m == nil {
		t.Fatalf("failed to create device manager")
	}

	// A DRA/CDI-injected MIG GPU node: char device 195:0 destined at /dev/nvidia0.
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

	// The device returned to runc must have its Path cleared (R-a: skip runc bind).
	if len(resolved) != 1 || resolved[0].Path != "" {
		t.Fatalf("SetupDevices must return a single Path-cleared device, got %+v", resolved)
	}

	// DeviceMounts must emit a bind from the materialized node to /dev/nvidia0.
	mounts := m.DeviceMounts("cid-test")
	if len(mounts) != 1 {
		t.Fatalf("expected exactly one device mount, got %d", len(mounts))
	}
	if mounts[0].Destination != "/dev/nvidia0" {
		t.Errorf("device mount destination mismatch: got %q", mounts[0].Destination)
	}
	if mounts[0].Type != "bind" {
		t.Errorf("device mount type mismatch: got %q", mounts[0].Type)
	}

	// The bind source (the materialized node) must exist under hostDir/cid.
	if _, err := os.Stat(mounts[0].Source); err != nil {
		t.Errorf("materialized node %s does not exist: %v", mounts[0].Source, err)
	}

	if err := m.RemoveDevices("cid-test"); err != nil {
		t.Fatalf("RemoveDevices returned error: %v", err)
	}
}

var modeChar = os.ModeCharDevice
