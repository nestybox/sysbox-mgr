package amd

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Placeholder for AMD GPU devicer implementation.

type amdDevicer struct{}

func NewAmdDevicer() *amdDevicer {
	return &amdDevicer{}
}

func (d *amdDevicer) Discover(dev *specs.LinuxDevice) (*specs.LinuxDevice, error) {
	return nil, nil
}

func (d *amdDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *amdDevicer) CreateByDefault() bool {
	return false
}
