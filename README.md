# sysbox-mgr

The Sysbox Manager (aka sysbox-mgr) is a daemon that
provides miscellaneous services to other sysbox components.

Currently it provides these services:

* subid allocation: allocates an exclusive range of subuid and subgids
  for each system container; service is invoked by sysbox-runc.

* docker-store-volume-management: creates a directory on the host
  that is mounted into the system container's `/var/lib/docker`.
  This way, the overlayfs over overlayfs scenario created by running
  docker-in-docker is avoided.

In the future it is expected to provide further services to sysbox-runc
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
