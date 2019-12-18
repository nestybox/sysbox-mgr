module github.com/nestybox/sysbox-mgr

go 1.13

require (
	github.com/deckarep/golang-set v1.7.1
	github.com/fsnotify/fsnotify v1.4.7
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/nestybox/sysbox-ipc v0.1.3
	github.com/nestybox/sysbox-runc v0.1.2
	github.com/opencontainers/runc v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runtime-spec v1.0.2-0.20191218002532-bab266ed033b
	github.com/sirupsen/logrus v1.4.2
	github.com/urfave/cli v1.20.0
	golang.org/x/sys v0.0.0-20190602015325-4c4f7f33c9ed
)

replace github.com/nestybox/sysbox-ipc => ../sysbox-ipc

replace github.com/nestybox/sysbox-runc => ../sysbox-runc

replace github.com/opencontainers/runc => ./../sysbox-runc
