package intel

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Placeholder for Intel GPU devicer implementation.

type intelDevicer struct{}

func NewIntelDevicer() *intelDevicer {
	return &intelDevicer{}
}

func (d *intelDevicer) Discover(dev *specs.LinuxDevice) (*specs.LinuxDevice, error) {
	return nil, nil
}

func (d *intelDevicer) Create(device *specs.LinuxDevice) error {
	return nil
}

func (d *intelDevicer) CreateByDefault() bool {
	return false
}
