package nvidia

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// Nvidia GPU devicer implementation.
//
// In DRA/CDI Kubernetes environments (nvidia-gpu-operator), container-destined nvidia
// device nodes almost never exist at their container path on the host:
//
//   - MIG capability nodes (e.g. /dev/nvidia-caps/nvidia-cap<N>) live under a 0700
//     root-owned /dev/nvidia-caps directory on the host, so mounting them by path fails
//     with EACCES during traversal.
//   - Driver nodes (e.g. /dev/nvidia0) live under the operator's driver root
//     (/run/nvidia/driver/dev), not at /dev, so a path rewrite alone would surface them
//     at the wrong container path that CUDA never looks at.
//
// To work around both, the devicer materializes every nvidia node whose container path
// is under /dev itself: it returns a "toCreate" node (preserving Path, Type, Major,
// Minor, FileMode) that the device manager mknods under sysboxDevDir and bind-mounts
// into the container, and it returns a Path-cleared discovered device so sysbox-runc
// skips its own node creation/binding (an empty Path makes createDeviceNode() a no-op).
//
// For nvidia nodes whose container path is NOT under /dev (e.g. paths injected by
// nvidia-container-runtime that point directly into a driver directory), it keeps the
// traditional behavior: rewrite the path to the host location where the node exists so
// sysbox-runc can bind-mount it.

// Known paths of Nvidia GPU devices in the host.
var nvidiaDeviceDirs = []string{
	"/",                  // Default path used by the traditional nvidia-driver installer.
	"/run/nvidia/driver", // Default path used by the nvidia-gpu-operator.
}

type nvidiaDevicer struct{}

func NewNvidiaDevicer() *nvidiaDevicer {
	return &nvidiaDevicer{}
}

// isNvidiaDevPath returns true if the device's container path is an nvidia GPU or
// MIG capability node under /dev (e.g., /dev/nvidia0, /dev/nvidiactl,
// /dev/nvidia-modeset, /dev/nvidia-uvm, /dev/nvidia-uvm-tools,
// /dev/nvidia-caps/nvidia-cap<N>).
func isNvidiaDevPath(path string) bool {
	return strings.HasPrefix(path, "/dev/nvidia")
}

func (d *nvidiaDevicer) Discover(dev *specs.LinuxDevice) (*specs.LinuxDevice, []*specs.LinuxDevice, error) {
	if dev == nil {
		return nil, nil, nil
	}

	// In DRA/CDI Kubernetes environments (nvidia-gpu-operator), the container-destined
	// nvidia device nodes never exist at their container path on the host: the MIG
	// capability nodes live under /dev/nvidia-caps which is 0700 root-owned on the host,
	// and the driver nodes live under the operator's driver root (/run/nvidia/driver/dev),
	// not at /dev. Returning the device to sysbox-runc would make it bind-mount a host
	// source that is either unreachable (EACCES on /dev/nvidia-caps) or at the wrong
	// container path (operator root relocates /dev/nvidia0 -> /run/nvidia/driver/dev,
	// which CUDA never looks at).
	//
	// So for every nvidia node whose container path is under /dev we materialize the node
	// ourselves from its (major, minor, FileMode) (as provided by the DRA/CDI allocator)
	// under sysboxDevDir via createDevice(), and return a Path-cleared device to
	// sysbox-runc so that runc skips its own node creation/binding (an empty Path makes
	// createDeviceNode() a no-op) and the node reaches the container only through the
	// DeviceMounts() bind (Source sysboxDevDir/<cid>/<path>, Destination <path>).
	if isNvidiaDevPath(dev.Path) {
		if dev.Type != "c" || dev.Major <= 0 || dev.FileMode == nil {
			return nil, nil, nil
		}
		materialize := *dev
		// Force the character-device bit on the mode we hand to createDevice(). The
		// OCI/CDI allocator only provides pure permission bits (0666/0444) in
		// FileMode; the type is conveyed via Type=="c". Setting S_IFCHR here (plus
		// the createDevice() Type-based guard) ensures the node is mknod'ed as a
		// character device rather than a regular file.
		mode := os.ModeCharDevice | *dev.FileMode
		materialize.FileMode = &mode
		discovered := *dev
		discovered.Path = ""
		return &discovered, []*specs.LinuxDevice{&materialize}, nil
	}

	// For nvidia nodes whose container path is NOT under /dev (e.g., paths provided by
	// nvidia-container-runtime pointing directly into a driver directory), keep the
	// traditional behavior: rewrite the path to the host location where the node exists so
	// sysbox-runc can bind-mount it.
	for _, dir := range nvidiaDeviceDirs {
		devHostPath := filepath.Join(dir, dev.Path)
		if _, err := os.Stat(devHostPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			// Unexpected error
			return nil, nil, err
		}

		// Update the device path to point to the nvidia driver directory where the device
		// node is created in the host by the nvidia-container-runtime plugins.
		rewritten := *dev
		rewritten.Path = devHostPath
		return &rewritten, nil, nil
	}

	return nil, nil, nil
}

func (d *nvidiaDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *nvidiaDevicer) CreateByDefault() bool {
	return false
}
