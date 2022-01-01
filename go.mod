module github.com/nestybox/sysbox-mgr

go 1.13

require (
	github.com/containerd/containerd v1.4.11
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/deckarep/golang-set v1.7.1
	github.com/fsnotify/fsnotify v1.4.7
	github.com/google/uuid v1.1.2
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531
	github.com/joshlf/testutil v0.0.0-20170608050642-b5d8aa79d93d // indirect
	github.com/karrick/godirwalk v1.16.1
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/dockerUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/formatter v0.0.0-20211230192847-357e78e444bd
	github.com/nestybox/sysbox-libs/idShiftUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/utils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-runc v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runc v1.0.0-rc9.0.20210126000000-2be806d1391d
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/pkg/profile v1.5.0
	github.com/sirupsen/logrus v1.7.0
	github.com/urfave/cli v1.22.1
	golang.org/x/sys v0.0.0-20201107080550-4d91cf3a1aaf
)

replace github.com/nestybox/sysbox-ipc => ../sysbox-ipc

replace github.com/nestybox/sysbox-runc => ../sysbox-runc

replace github.com/nestybox/sysbox-libs/utils => ../sysbox-libs/utils

replace github.com/nestybox/sysbox-libs/formatter => ../sysbox-libs/formatter

replace github.com/nestybox/sysbox-libs/dockerUtils => ../sysbox-libs/dockerUtils

replace github.com/nestybox/sysbox-libs/idShiftUtils => ../sysbox-libs/idShiftUtils

replace github.com/nestybox/sysbox-libs/libseccomp-golang => ../sysbox-libs/libseccomp-golang

replace github.com/nestybox/sysbox-libs/capability => ../sysbox-libs/capability

replace github.com/opencontainers/runc => ./../sysbox-runc

replace github.com/godbus/dbus => github.com/godbus/dbus/v5 v5.0.3
