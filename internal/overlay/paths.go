//
// Copyright 2019-2023 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package overlay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nestybox/sysbox-libs/overlayUtils"
)

// MountBase returns the directory against which relative overlayfs
// lowerdir paths are resolved. Containerd keeps upperdir absolute when it
// shortens lowerdir paths, so the common base can be derived from upperdir.
// Docker's overlay2 driver shortens upperdir and workdir too. It mounts rootfs
// at <base>/<id>/merged and uses <id>/diff as upperdir, so the common base can
// be derived from the rootfs mountpoint. Changing to the returned directory
// makes all of those relative paths resolve correctly.
func MountBase(rootfs, upperLayer string, lowerLayers []string) (string, bool) {
	if len(lowerLayers) == 0 || filepath.IsAbs(lowerLayers[0]) {
		return "", false
	}

	anchor := upperLayer
	relativePath := lowerLayers[0]
	if !filepath.IsAbs(upperLayer) {
		anchor = rootfs
		relativePath = upperLayer
	}

	relativePath = filepath.Clean(relativePath)
	base := anchor
	for range strings.Split(relativePath, string(os.PathSeparator)) {
		base = filepath.Dir(base)
	}

	return base, true
}

func ValidateMountBase(base, lowerLayer string) error {
	resolvedLayer := filepath.Join(base, lowerLayer)
	if _, err := os.Stat(resolvedLayer); err != nil {
		return fmt.Errorf("cannot resolve relative overlay paths: %s: %w", resolvedLayer, err)
	}
	return nil
}

func ResolvePath(base, path string) string {
	if base == "" || path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// UpperLayer returns the overlay upperdir as an absolute path for use outside
// the mounting process's cwd. Absolute and missing upperdirs are unchanged.
func UpperLayer(rootfs string, opts *overlayUtils.MountOpts) (string, error) {
	upper := overlayUtils.GetUpperLayer(opts)
	if upper == "" || filepath.IsAbs(upper) {
		return upper, nil
	}

	lower := overlayUtils.GetLowerLayers(opts)
	base, relative := MountBase(rootfs, upper, lower)
	if relative {
		if err := ValidateMountBase(base, lower[0]); err != nil {
			return "", err
		}
	}
	return ResolvePath(base, upper), nil
}
