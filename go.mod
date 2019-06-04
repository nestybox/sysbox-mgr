module github.com/nestybox/sysvisor-mgr

go 1.13

require (
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/nestybox/sysvisor-ipc v0.0.0-20190603003818-483605a8fbcf
	github.com/nestybox/sysvisor-runc v0.1.2
	github.com/opencontainers/runtime-spec v0.1.2-0.20190207185410-29686dbc5559
	github.com/sirupsen/logrus v1.4.2
	github.com/urfave/cli v1.20.0
	golang.org/x/sys v0.0.0-20190602015325-4c4f7f33c9ed
)

replace github.com/opencontainers/runc v0.0.0-00010101000000-000000000000 => ../sysvisor-runc
