package net

import (
	"fmt"
	"os"
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// Network devicer implementation.

type netDevicer struct{}

const netTunPath = "/dev/net/tun"

func NewNetDevicer() *netDevicer {
	return &netDevicer{}
}

// This Discover() implementation currently only supports the /dev/net/tun
// device.
func (d *netDevicer) Discover(dev *specs.LinuxDevice) (*specs.LinuxDevice, error) {

	// Return cleanly if the specified device is not supported.
	if dev != nil && dev.Path != netTunPath {
		return nil, nil
	}

	// Discover the /dev/net/tun device.
	netTunDev, err := discoverNetTunDev()
	if err != nil {
		return nil, fmt.Errorf("failed to discover network devices: %v", err)
	}

	// Return cleanly if no network devices were discovered (assuming no error occurred).
	if netTunDev == nil {
		return nil, nil
	}

	return netTunDev, nil
}

func (d *netDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *netDevicer) CreateByDefault() bool {
	return true
}

func discoverNetTunDev() (*specs.LinuxDevice, error) {
	info, err := os.Stat(netTunPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to discover ethernet-tun device %s: %v", netTunPath, err)
	}

	fileMode := info.Mode()

	dev := &specs.LinuxDevice{
		Path:     netTunPath,
		Type:     "c",
		Major:    int64(unix.Major(uint64(info.Sys().(*syscall.Stat_t).Rdev))),
		Minor:    int64(unix.Minor(uint64(info.Sys().(*syscall.Stat_t).Rdev))),
		FileMode: &fileMode,
	}

	return dev, nil
}
