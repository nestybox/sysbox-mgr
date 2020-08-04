# sysbox-mgr

The Sysbox Manager (aka sysbox-mgr) is a daemon that
provides miscellaneous services to other sysbox components.

Currently it provides these services:

* Subid allocation: allocates a common range of subuid and subgids
  for all system containers; service is invoked by sysbox-runc.

* Shiftfs marking: creates shiftfs marks on host directories on
  which shiftfs will be mounted. Handles redundant mounts/unmounts
  of shiftfs on the same directory.

* Mount ownership changes: changes ownership on host directories
  that are bind-mounted into the sys container and on top of
  which shiftfs mounting is not possible.

* Docker-store Volume Management: creates a directory on the host
  that is mounted into the system container's `/var/lib/docker`.
  This way, the overlayfs over overlayfs scenario created by running
  docker-in-docker is avoided.

* Kubelet-store Volume Management: creates a directory on the host
  that is mounted into the system container's `/var/lib/kubelet`.
  This is needed to avoid shiftfs mounts over this directory in
  the sys container, as kubelet does not support it.

* Docker-store Volume Management: creates a directory on the host
  that is mounted into the system container's `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs`.
  This way, the overlayfs over overlayfs scenario created by running
  containerd-in-docker is avoided.

In the future it's expected to provide further services to sysbox-runc
as well as sysbox-fs.

# Build & Usage

sysbox-mgr is built with the sysbox Makefile. Refer to that sysbox
[README](../README.md) file for details.

# gRPC

sysbox-mgr listens on a unix-domain socket for gRPC from other sysbox
components.

Currently a single gRPC is used (between sysbox-runc and sysbox-mgr).

In the future other gRPCs may be created (e.g,. for communication
between sysbox-fs and sysbox-mgr).
