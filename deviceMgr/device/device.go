package device

import "io/fs"

// deviceInfo contains information about a device.
type DevInfo struct {
	Name        string
	Brand       string
	Product     string
	Src         string
	Dst         string
	Major       uint32
	Minor       uint32
	Uid         uint32
	Gid         uint32
	Mode        fs.FileMode
	Cid         string
	DefaultInit bool
}
