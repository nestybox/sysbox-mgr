module github.com/nestybox/sysbox-mgr

go 1.13

require (
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/deckarep/golang-set v1.7.1
	github.com/fsnotify/fsnotify v1.4.7
	github.com/google/uuid v1.1.2
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/dockerUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/formatter v0.0.0-20211230192847-357e78e444bd
	github.com/nestybox/sysbox-libs/idMap v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/idShiftUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/linuxUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/mount v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/overlayUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/shiftfs v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/utils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-runc v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runc v1.0.0-rc9.0.20210126000000-2be806d1391d
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/pkg/profile v1.5.0
	github.com/sirupsen/logrus v1.9.0
	github.com/urfave/cli v1.22.1
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
)

replace (
	github.com/godbus/dbus => github.com/godbus/dbus/v5 v5.0.3
	github.com/nestybox/sysbox-ipc => ../sysbox-ipc
	github.com/nestybox/sysbox-libs/capability => ../sysbox-libs/capability
	github.com/nestybox/sysbox-libs/dockerUtils => ../sysbox-libs/dockerUtils
	github.com/nestybox/sysbox-libs/formatter => ../sysbox-libs/formatter
	github.com/nestybox/sysbox-libs/idMap => ../sysbox-libs/idMap
	github.com/nestybox/sysbox-libs/idShiftUtils => ../sysbox-libs/idShiftUtils
	github.com/nestybox/sysbox-libs/libseccomp-golang => ../sysbox-libs/libseccomp-golang
	github.com/nestybox/sysbox-libs/linuxUtils => ../sysbox-libs/linuxUtils
	github.com/nestybox/sysbox-libs/mount => ../sysbox-libs/mount
	github.com/nestybox/sysbox-libs/overlayUtils => ../sysbox-libs/overlayUtils
	github.com/nestybox/sysbox-libs/shiftfs => ../sysbox-libs/shiftfs
	github.com/nestybox/sysbox-libs/utils => ../sysbox-libs/utils
	github.com/nestybox/sysbox-runc => ../sysbox-runc
	github.com/opencontainers/runc => ./../sysbox-runc
)
