//go:build linux
// +build linux

package overlay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nestybox/sysbox-libs/overlayUtils"
)

func TestOverlayMountBase(t *testing.T) {
	tests := []struct {
		name         string
		rootfs       string
		upperLayer   string
		lowerLayers  []string
		wantBase     string
		wantRelative bool
	}{
		{
			name:        "absolute lowerdirs need no base",
			rootfs:      "/var/lib/docker/overlay2/container/merged",
			upperLayer:  "/var/lib/docker/overlay2/container/diff",
			lowerLayers: []string{"/var/lib/docker/overlay2/l/layer-one"},
		},
		{
			name:         "containerd relative lowerdirs with absolute upperdir",
			rootfs:       "/run/containerd/io.containerd.runtime.v2.task/default/container/rootfs",
			upperLayer:   "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/55/fs",
			lowerLayers:  []string{"54/fs", "44/fs"},
			wantBase:     "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots",
			wantRelative: true,
		},
		{
			name:         "containerd relative lowerdir with trailing slash",
			rootfs:       "/run/containerd/io.containerd.runtime.v2.task/default/container/rootfs",
			upperLayer:   "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/55/fs",
			lowerLayers:  []string{"54/fs/"},
			wantBase:     "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots",
			wantRelative: true,
		},
		{
			name:         "docker overlay2 relative lowerdir and upperdir",
			rootfs:       "/var/lib/docker/overlay2/container/merged",
			upperLayer:   "container/diff",
			lowerLayers:  []string{"l/layer-one", "l/layer-two"},
			wantBase:     "/var/lib/docker/overlay2",
			wantRelative: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, relative := MountBase(tc.rootfs, tc.upperLayer, tc.lowerLayers)
			if base != tc.wantBase {
				t.Errorf("MountBase() base = %q, want %q", base, tc.wantBase)
			}
			if relative != tc.wantRelative {
				t.Errorf("MountBase() relative = %v, want %v", relative, tc.wantRelative)
			}
		})
	}
}

func TestValidateOverlayMountBase(t *testing.T) {
	base := t.TempDir()
	lowerLayer := filepath.Join("l", "layer-one")
	if err := os.MkdirAll(filepath.Join(base, lowerLayer), 0755); err != nil {
		t.Fatal(err)
	}

	if err := ValidateMountBase(base, lowerLayer); err != nil {
		t.Fatalf("ValidateMountBase() unexpected error: %v", err)
	}

	err := ValidateMountBase(base, filepath.Join("l", "missing-layer"))
	if err == nil {
		t.Fatal("ValidateMountBase() expected error")
	}
	if !strings.Contains(err.Error(), "cannot resolve relative overlay paths") {
		t.Fatalf("ValidateMountBase() error = %q", err)
	}
}

func TestResolveOverlayPath(t *testing.T) {
	const base = "/var/lib/docker/overlay2"

	tests := []struct {
		name string
		base string
		path string
		want string
	}{
		{
			name: "relative upperdir",
			base: base,
			path: "container/diff",
			want: "/var/lib/docker/overlay2/container/diff",
		},
		{
			name: "relative workdir",
			base: base,
			path: "container/work",
			want: "/var/lib/docker/overlay2/container/work",
		},
		{
			name: "absolute path",
			base: base,
			path: "/var/lib/docker/overlay2/container/diff",
			want: "/var/lib/docker/overlay2/container/diff",
		},
		{
			name: "missing path stays empty",
			base: base,
		},
		{
			name: "no base leaves path unchanged",
			path: "container/diff",
			want: "container/diff",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolvePath(tc.base, tc.path); got != tc.want {
				t.Errorf("ResolvePath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUpperLayer(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "l", "layer-one"), 0755); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(base, "container", "merged")
	upper := filepath.Join(base, "container", "diff")
	tests := []struct {
		name    string
		options string
		want    string
		wantErr string
	}{
		{
			name:    "docker relative upperdir",
			options: "lowerdir=l/layer-one,upperdir=container/diff,workdir=container/work",
			want:    upper,
		},
		{
			name:    "docker relative upperdir with trailing slash",
			options: "lowerdir=l/layer-one,upperdir=container/diff/",
			want:    upper,
		},
		{
			name:    "absolute upperdir",
			options: "lowerdir=/layers/one,upperdir=" + upper,
			want:    upper,
		},
		{
			name:    "containerd absolute upperdir with relative lowerdir",
			options: "lowerdir=54/fs,upperdir=/snapshots/55/fs",
			want:    "/snapshots/55/fs",
		},
		{
			name:    "missing upperdir",
			options: "lowerdir=l/layer-one",
		},
		{
			name:    "invalid base",
			options: "lowerdir=l/missing-layer,upperdir=container/diff",
			wantErr: "cannot resolve relative overlay paths: " + filepath.Join(base, "l", "missing-layer"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UpperLayer(rootfs, &overlayUtils.MountOpts{Opts: tc.options})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("UpperLayer() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("UpperLayer() = %q, want %q", got, tc.want)
			}
		})
	}
}
