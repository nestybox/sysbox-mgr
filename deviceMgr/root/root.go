package root

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Dummy devicer to serve as the root of the devicer's radix-tree.

type rootDevicer struct{}

func NewRootDevicer() *rootDevicer {
	return &rootDevicer{}
}

func (d *rootDevicer) Discover(dev *specs.LinuxDevice) (*specs.LinuxDevice, error) {
	return nil, nil
}

func (d *rootDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *rootDevicer) CreateByDefault() bool {
	return false
}
