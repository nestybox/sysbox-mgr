package nvidia

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// Nvidia GPU devicer implementation.
//
// This devicer implementation currently only supports the utilization of Nvidia GPU
// devices in Kubernetes environments. In this environment, the Nvidia GPU devices are
// typically made available to the containerized workloads via the nvidia-container-runtime
// plugins, which are invoked by sysbox-runc through the OCI hooks mechanism. The nvidia-
// container-runtime plugins are responsible for creating the device nodes in the host and
// mounting them into the container's filesystem (along with other necessary bind-mounts).
// Since most of the heavy-lifting is done by the nvidia-container-runtime plugins, the
// devicer implementation here is quite simple: it simply updates the device path to point
// to the nvidia driver directory where the device node is created in the host by the
// nvidia-container-runtime plugins.

// Known paths of Nvidia GPU devices in the host.
var nvidiaDeviceDirs = []string{
	"/",                  // Default path used by the traditional nvidia-driver installer.
	"/run/nvidia/driver", // Default path used by the nvidia-gpu-operator.
}

// nvidiaCapsDir is the host directory where the nvidia capability nodes (including the
// per-MIG-slice capability nodes) are exposed.
const nvidiaCapsDir = "/dev/nvidia-caps"

type nvidiaDevicer struct{}

func NewNvidiaDevicer() *nvidiaDevicer {
	return &nvidiaDevicer{}
}

func (d *nvidiaDevicer) Discover(dev *specs.LinuxDevice) (*specs.LinuxDevice, error) {
	if dev == nil {
		return nil, nil
	}

	for _, dir := range nvidiaDeviceDirs {
		devHostPath := filepath.Join(dir, dev.Path)
		if _, err := os.Stat(devHostPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			// Unexpected error
			return nil, err
		}

		// Update the device path to point to the nvidia driver directory where the device
		// node is created in the host by the nvidia-container-runtime plugins.
		dev.Path = devHostPath
		return dev, nil
	}

	// The nvidia device node was not found in any of the known host directories. In the
	// case of MIG capability nodes (e.g. /dev/nvidia-caps/nvidia-cap75), the node is
	// normally created in-container by libcontainer (mknod) from its (major, minor) pair
	// that is provided by the DRA/CDI allocator. When sysbox is used, however, sysbox-runc
	// bind-mounts the node from a host source that is expected to already exist. In the
	// sysbox environment the nvidia driver is containerized (gpu-operator), so per-slice
	// capability nodes never materialize on the host. To make the MIG slices work under
	// sysbox we create the missing capability node on the host (sysbox-mgr runs as root on
	// the host) from the (major, minor) pair provided by the allocator; sysbox-runc then
	// bind-mounts this node into the container.
	if isMigCapNode(dev) {
		mknodMigCapNode(dev)
		if _, err := os.Stat(dev.Path); err == nil {
			return dev, nil
		}
	}

	return nil, nil
}

// isMigCapNode returns true if the given device is a nvidia MIG capability node. These
// nodes are character devices under /dev/nvidia-caps/ named nvidia-cap<minor>, where
// <minor> corresponds to a specific MIG slice's capability minor number.
func isMigCapNode(dev *specs.LinuxDevice) bool {
	if dev == nil || dev.Type != "c" {
		return false
	}
	clean := filepath.Clean(dev.Path)
	return strings.HasPrefix(clean, filepath.Join(nvidiaCapsDir, "nvidia-cap"))
}

// mknodMigCapNode creates the MIG capability node on the host at its container path so
// that sysbox-runc can bind-mount it into the container.
func mknodMigCapNode(dev *specs.LinuxDevice) {
	if dev == nil || dev.Major <= 0 || dev.Minor < 0 {
		return
	}

	hostDevPath := dev.Path
	if _, err := os.Stat(hostDevPath); err == nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(hostDevPath), 0700); err != nil {
		return
	}

	mode := uint32(unix.S_IFCHR | 0600)
	if dev.FileMode != nil {
		mode = uint32(*dev.FileMode)
		if mode&uint32(os.ModeDevice) == 0 {
			mode |= uint32(unix.S_IFCHR)
		}
	}

	devNum := int(unix.Mkdev(uint32(dev.Major), uint32(dev.Minor)))
	if err := unix.Mknod(hostDevPath, mode, devNum); err != nil {
		return
	}
}

func (d *nvidiaDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *nvidiaDevicer) CreateByDefault() bool {
	return false
}
