module github.com/nestybox/sysbox-mgr

go 1.18

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
	github.com/opencontainers/runc v1.1.4
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/pkg/profile v1.5.0
	github.com/sirupsen/logrus v1.9.0
	github.com/urfave/cli v1.22.1
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
)

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/containerd/containerd v1.4.12 // indirect
	github.com/coreos/go-systemd/v22 v22.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.2+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531 // indirect
	github.com/karrick/godirwalk v1.16.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/spf13/afero v1.4.1 // indirect
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b // indirect
	golang.org/x/text v0.3.8 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/grpc v1.34.1 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
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
