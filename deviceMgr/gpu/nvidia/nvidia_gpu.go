package nvidia

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"
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

	return nil, nil
}

func (d *nvidiaDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *nvidiaDevicer) CreateByDefault() bool {
	return false
}
