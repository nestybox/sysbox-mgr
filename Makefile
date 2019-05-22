#
# sysvisor-mgr Makefile
#
# Note: targets must execute from the $SYSMGR_GO_DIR

.PHONY: clean sysvisor-mgr-debug sysvisor-mgr-static

PROJECT := github.com/nestybox/sysvisor
SYSMGR_GO_DIR := $(GOPATH)/src/$(PROJECT)/sysvisor-mgr

SYSMGR_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')
SYSMGR_GRPC_DIR := ../sysvisor-ipc/sysvisorMgrGrpc
SYSMGR_GRPC_SRC := $(shell find $(SYSMGR_GRPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

sysvisor-mgr: $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC)
	go build -o sysvisor-mgr

sysvisor-mgr-debug: $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC)
	go build -gcflags="all=-N -l" -o sysvisor-mgr

sysvisor-mgr-static: $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC)
	CGO_ENABLED=1 go build -tags "netgo osusergo static_build" -installsuffix netgo -ldflags "-w -extldflags -static" -o sysvisor-mgr

clean:
	rm -f sysvisor-mgr
