#
# sysvisor-mgr Makefile
#
# Note: targets must execute from the $SYSMGR_DIR

.PHONY: clean sysvisor-mgr-debug sysvisor-mgr-static

# Let's make use of go's top-of-tree binary till 1.13 comes out.
GO := gotip

SYSMGR_DIR := $(CURDIR)
SYSMGR_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

SYSMGR_GRPC_DIR := ../sysvisor-ipc/sysvisorMgrGrpc
SYSMGR_GRPC_SRC := $(shell find $(SYSMGR_GRPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

LDFLAGS := '-X main.version=${VERSION} -X main.commitId=${COMMIT_ID} \
			-X "main.builtAt=${BUILT_AT}" -X main.builtBy=${BUILT_BY}'

sysvisor-mgr: $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC)
	$(GO) build -ldflags ${LDFLAGS} -o sysvisor-mgr

sysvisor-mgr-debug: $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC)
	$(GO) build -gcflags="all=-N -l" -o sysvisor-mgr

sysvisor-mgr-static: $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC)
	CGO_ENABLED=1 $(GO) build -tags "netgo osusergo static_build" \
		-installsuffix netgo -ldflags "-w -extldflags -static" \
		-o sysvisor-mgr

clean:
	rm -f sysvisor-mgr
