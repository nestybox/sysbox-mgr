package deviceMgr

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	iradix "github.com/hashicorp/go-immutable-radix"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	amdGpu "github.com/nestybox/sysbox-mgr/deviceMgr/gpu/amd"
	intelGpu "github.com/nestybox/sysbox-mgr/deviceMgr/gpu/intel"
	nvidiaGpu "github.com/nestybox/sysbox-mgr/deviceMgr/gpu/nvidia"
	"github.com/nestybox/sysbox-mgr/deviceMgr/net"
	"github.com/nestybox/sysbox-mgr/deviceMgr/root"
)

// sysboxDevDir is the host directory where the devMgr's devices are created.
const sysboxDevDir = "/var/lib/sysbox/devices"

// devicer is the interface that wraps the methods required to obtain, configure
// and create devices in the system for a given device type.
type devicer interface {
	// Discover method finds out which of the deviceMgr's supported devices are
	// available in the host and their required configuration. Discover() takes
	// a device specification as input, and returns a device specification with the
	// requred adjustments to allow the device to be used within the container. In
	// certain cases, the required adjument may be as simple as setting the correct
	// device path in the device specification. If no device specification is
	// provided, Discover() may return the device specification for the devices
	// that must be created by default (e.g., /dev/net/tun).
	Discover(device *specs.LinuxDevice) (*specs.LinuxDevice, error)

	// Create method handles any device-specific instruction that may be required by
	// the device (currently not used).
	Create(device *specs.LinuxDevice) error

	// CreateByDefault returns true if the device must be created by default for
	// each container (regardless of the device specification in the oci-spec).
	// This is useful for devices that are normally present in the system, and that
	// are required for basic functionality (e.g., /dev/net/tun).
	CreateByDefault() bool
}

// External interface for the device manager.
type DeviceMgrIface interface {
	SetupDevices(cid string, uid, gid uint32, devices []specs.LinuxDevice) ([]specs.LinuxDevice, error)
	CreateDevices(cid string, uid, gid uint32, devices []specs.LinuxDevice) error
	RemoveDevices(cid string) error
	DeviceMounts(cid string) []specs.Mount
}

// DeviceMgr manages the devices that are available in the system and that can
// be potentially exposed to containers. The device manager is responsible for
// discovering the devices that are available in the system, configuring them
// as needed, and creating the device nodes in the host file-system for them.
type DeviceMgr struct {
	// hostDir is the host directory where device nodes are created.
	hostDir string

	// devicerTree is a radix-tree that indexes the supported devicers in the
	// system. The tree is indexed by the path prefix where each device is
	// typically held in the file-system; the value corresponds to the devicer
	// object associated to each particular device (e.g., /dev/net -> netDevicer).
	// The radix-tree is used to quickly find the devicer object that is a common
	// to a set of devices (e.g., /dev/nvidia0, /dev/nvidia1, /dev/nvidia2, etc.).
	// A map-based approach would require iterating through all the elements and
	// checking the longest prefix match based on string comparison, which is less
	// efficient than using a radix-tree.
	devicerTree *iradix.Tree

	// perCntDevMap keeps track of the devices created per-container. Entries are
	// indexed by the container ID, and the value is a slice of pointers to the
	// specs.LinuxDevice objects that hold the device information.
	perCntDevMap map[string][]*specs.LinuxDevice

	// mu protects the perCntDevMap object.
	mu sync.RWMutex
}

// NewDeviceMgr creates a new device manager.
func New(hostDir string) *DeviceMgr {
	m := &DeviceMgr{
		hostDir:      hostDir,
		perCntDevMap: make(map[string][]*specs.LinuxDevice),
	}

	if os.MkdirAll(hostDir, 0700) != nil {
		logrus.Errorf("failed to create device manager directory %s", hostDir)
		return nil
	}

	// Initialize the devicer radix-tree.
	m.devicerTree = iradix.New()
	if m.devicerTree == nil {
		logrus.Errorf("failed to create devicer tree")
		return nil
	}

	// Insert the supported devicers into the radix-tree.

	tree, _, _ := m.devicerTree.Insert([]byte("/"), root.NewRootDevicer())
	m.devicerTree = tree

	tree, _, _ = m.devicerTree.Insert([]byte("/dev/net"), net.NewNetDevicer())
	m.devicerTree = tree

	tree, _, _ = m.devicerTree.Insert([]byte("/dev/nvidia"), nvidiaGpu.NewNvidiaDevicer())
	m.devicerTree = tree

	tree, _, _ = m.devicerTree.Insert([]byte("/dev/amd"), amdGpu.NewAmdDevicer())
	m.devicerTree = tree

	tree, _, _ = m.devicerTree.Insert([]byte("/dev/intel"), intelGpu.NewIntelDevicer())
	m.devicerTree = tree

	return m
}

// CreateDevices creates, for a given container, the discovered devices in the device
// manager.
func (m *DeviceMgr) CreateDevices(cid string, uid, gid uint32, devices []specs.LinuxDevice) error {

	for _, d := range devices {
		if err := m.createDevice(cid, uid, gid, &d); err != nil {
			return fmt.Errorf("failed to create device %s for container %s: %s", d.Path, cid, err)
		}
	}

	return nil
}

// RemoveDevices removes all the previously created devices for a given container.
func (m *DeviceMgr) RemoveDevices(cid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, dev := range m.perCntDevMap[cid] {
		if err := m.removeDevice(cid, dev.Path); err != nil {
			return err
		}
	}
	delete(m.perCntDevMap, cid)

	// Remove the device directory for the container.
	devDir := filepath.Join(m.hostDir, cid)
	if err := os.RemoveAll(devDir); err != nil {
		return fmt.Errorf("failed to remove device directory %s: %s", devDir, err)
	}

	return nil
}

// SetupDevices takes care of discovering and configuring the devices received from
// sysbox-runc, and creating the devices that must be allocated by default for each
// container (e.g., /dev/net/tun). Notice that this "discovery" process is done at
// container startup time, since the available devices in the system may vary over
// time.
func (m *DeviceMgr) SetupDevices(
	cid string, uid, gid uint32, devices []specs.LinuxDevice) ([]specs.LinuxDevice, error) {

	var res []specs.LinuxDevice

	logrus.Debugf("Setting up devices %v for container %s", devices, cid)

	for _, d := range devices {
		// Iterate the devicer tree looking for the devicer that better matches the device.
		//
		// If the device to setup is not currently supported by this devMgr, skip it, but
		// first add it to the list of devices that will be returned to sysbox-runc so that
		// we don't alter the original oci-spec.
		devicerPath, node, ok := m.devicerTree.Root().LongestPrefix([]byte(d.Path))
		if !ok || string(devicerPath) == "/" {
			res = append(res, d)
			continue
		}
		devicer := node.(devicer)

		// Discover the device.
		discoveredDev, err := devicer.Discover(&d)
		if err != nil {
			return nil, fmt.Errorf("failed to discover device %s: %s", d.Path, err)
		}
		// If the device cannot be discovered, add the original device to the list of devices
		// that will be returned to sysbox-runc so that this one returns an error to the user.
		if discoveredDev == nil {
			res = append(res, d)
			continue
		}
		res = append(res, *discoveredDev)
	}

	// Iterate through the devicer tree and create the devices that must be allocated
	// by default for each container.
	it := m.devicerTree.Root().Iterator()
	for {
		_, node, ok := it.Next()
		if !ok {
			break
		}
		d := node.(devicer)
		if !d.CreateByDefault() {
			continue
		}
		discoveredDev, err := d.Discover(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to discover default device: %s", err)
		}
		if err := m.createDevice(cid, uid, gid, discoveredDev); err != nil {
			return nil, fmt.Errorf("failed to create default device for container %s: %s", cid, err)
		}
	}

	logrus.Debugf("Devices %v successfully setup for container %s", res, cid)

	return res, nil
}

// DeviceMounts returns the device mounts for the specified container. The device mounts
// are created for every device that is implicitly or explicitly created by the device
// manager. These mounts are used by sysbox-runc to bind-mount the device nodes into the
// container's file-system.
func (m *DeviceMgr) DeviceMounts(cid string) []specs.Mount {
	var mounts []specs.Mount

	m.mu.RLock()
	defer m.mu.RUnlock()

	devSlice, ok := m.perCntDevMap[cid]
	if !ok {
		// No devices for this container. Shouldn't ever happen.
		return mounts
	}

	for _, d := range devSlice {
		hostDevPath := filepath.Join(m.hostDir, cid, d.Path)

		mounts = append(mounts, specs.Mount{
			Source:      hostDevPath,
			Destination: d.Path,
			Type:        "bind",
			Options:     []string{"rbind", "rw"},
		})
	}

	logrus.Debugf("Device mounts for container %s: %v", cid, mounts)

	return mounts
}

// createDevice creates a device node in the host file-system for a given device
// specification.
func (m *DeviceMgr) createDevice(cid string, uid, gid uint32, dev *specs.LinuxDevice) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if dev == nil {
		return fmt.Errorf("invalid device specification")
	}

	if dev.UID == nil {
		dev.UID = &uid
	}
	if dev.GID == nil {
		dev.GID = &gid
	}

	// Check if the device already exists in the device manager.
	devSlice, ok := m.perCntDevMap[cid]
	if ok {
		for _, curDev := range devSlice {
			if curDev.Path == dev.Path {
				return fmt.Errorf("device %s already exists in container %s", dev.Path, cid)
			}
		}
	}

	// Check if the device node already exists in the host.
	hostDevPath := filepath.Join(m.hostDir, cid, dev.Path)
	if _, err := os.Stat(hostDevPath); err == nil {
		return fmt.Errorf("device %s already exists in host system", hostDevPath)
	}

	// Create the parent directory if it does not exist.
	if err := os.MkdirAll(filepath.Dir(hostDevPath), 0700); err != nil {
		return fmt.Errorf("failed to create device %s: %s", hostDevPath, err)
	}

	// TODO: handle other device types.
	if *dev.FileMode&fs.ModeCharDevice != 0 {
		*dev.FileMode |= unix.S_IFCHR
	}

	// Create the device node.
	devNum := int(unix.Mkdev(uint32(dev.Major), uint32(dev.Minor)))
	err := unix.Mknod(hostDevPath, uint32(*dev.FileMode), devNum)
	if err != nil {
		return fmt.Errorf("failed to create device %s: %s", hostDevPath, err)
	}

	// Set the device node ownership and permissions.
	if err := os.Chown(hostDevPath, int(*dev.UID), int(*dev.GID)); err != nil {
		return fmt.Errorf("failed to set ownership of device %s: %s", hostDevPath, err)
	}

	if err := os.Chmod(hostDevPath, *dev.FileMode); err != nil {
		return fmt.Errorf("failed to set permissions of device %s: %s", hostDevPath, err)
	}

	// Add the device to the device manager.
	devSlice, ok = m.perCntDevMap[cid]
	if ok {
		devSlice = append(devSlice, dev)
		m.perCntDevMap[cid] = devSlice
	} else {
		m.perCntDevMap[cid] = []*specs.LinuxDevice{dev}
	}

	return nil
}

// removeDevice removes a device from the device manager. Notice that callee must hold the
// lock to the device manager before calling this function.
func (m *DeviceMgr) removeDevice(cid, name string) error {

	// Verify that the device has been registered in the device manager.
	devSlice, ok := m.perCntDevMap[cid]
	if !ok {
		return nil
	}

	var found bool
	for _, dev := range devSlice {
		if dev.Path == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("device %s does not exist in container %s", name, cid)
	}

	// Remove the device from the device manager.
	var newDevSlice []*specs.LinuxDevice
	for _, dev := range devSlice {
		if dev.Path != name {
			newDevSlice = append(newDevSlice, dev)
		}
	}
	m.perCntDevMap[cid] = newDevSlice

	// Verify that the device node exists on the host and remove it.
	hostDevPath := filepath.Join(m.hostDir, cid, name)
	if _, err := os.Stat(hostDevPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("device %s does not exist in host system", hostDevPath)
		}
		return fmt.Errorf("failed to stat device %s: %s", hostDevPath, err)
	}
	if err := os.Remove(hostDevPath); err != nil {
		return fmt.Errorf("failed to remove device %s: %s", hostDevPath, err)
	}

	return nil
}
