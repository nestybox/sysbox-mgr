# sysvisor-mgr

The Sysvisor Manager (aka sysvisor-mgr) is a daemon that
provides miscellaneous services to other sysvisor-components.

Currently it provides these services:

* subid allocation: allocates an exclusive range of subuid and subgids
  for each container; service is invoked by sysvisor-runc.

In the future it is expected to provide further services to sysvisor-runc
as well as sysvisor-fs.

# Build

sysvisor-mgr is build with the sysvisor Makefile.

```
cd sysvisor
make && sudo make install
```

# Usage

```
$ sudo sysvisor-mgr
```

# gRPC

sysvisor-mgr listens on a unix-domain socket(s) for gRPC from other
sysvisor components.

Currently a single gRPC is used (between sysvisor-runc and sysvisor-mgr).

In the future other gRPCs may be created (e.g,. for communication between
sysvisor-fs and sysvisor-mgr).
