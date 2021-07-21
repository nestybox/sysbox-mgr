#
# sysbox-mgr Makefile
#
# Note: targets must execute from the $SYSMGR_DIR

.PHONY: clean sysbox-mgr-debug sysbox-mgr-static lint list-packages

GO := go
ARCH := amd64

SYSMGR_BUILDROOT := build
SYSMGR_BUILDDIR := $(SYSMGR_BUILDROOT)/$(ARCH)
SYSMGR_TARGET := sysbox-mgr
SYSMGR_DEBUG_TARGET := sysbox-mgr-debug
SYSMGR_STATIC_TARGET := sysbox-mgr-static
SYSMGR_DIR := $(CURDIR)
SYSMGR_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

SYSMGR_GRPC_DIR := ../sysbox-ipc/sysboxMgrGrpc
SYSMGR_GRPC_SRC := $(shell find $(SYSMGR_GRPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

LIBDOCKER_DIR := ../sysbox-libs/dockerUtils
LIBDOCKER_SRC := $(shell find $(LIBDOCKER_DIR) 2>&1 | grep -E '.*\.(go)')

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_NO)-dirty,$(COMMIT_NO))
BUILT_AT := $(shell date)
BUILT_BY := $(shell git config user.name)

LDFLAGS := '-X "main.edition=${EDITION}" -X main.version=${VERSION} \
		-X main.commitId=$(COMMIT) -X "main.builtAt=$(BUILT_AT)" \
		-X "main.builtBy=$(BUILT_BY)"'

ifeq ($(ARCH),armel)
	GO_XCOMPILE := CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 CC=arm-linux-gnueabi-gcc
else ifeq ($(ARCH),armhf)
	GO_XCOMPILE := CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc
else ifeq ($(ARCH),arm64)
	GO_XCOMPILE = CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc
else
	GO_XCOMPILE = GOARCH=amd64
endif

.DEFAULT: sysbox-mgr

$(SYSMGR_BUILDDIR)/$(SYSMGR_TARGET): $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC) $(LIBDOCKER_SRC)
	$(GO_XCOMPILE) $(GO) build -ldflags ${LDFLAGS} -o $(SYSMGR_BUILDDIR)/sysbox-mgr

sysbox-mgr: $(SYSMGR_BUILDDIR)/$(SYSMGR_TARGET)

$(SYSMGR_BUILDDIR)/$(SYSMGR_DEBUG_TARGET): $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC) $(LIBDOCKER_SRC)
	$(GO_XCOMPILE) $(GO) build -gcflags="all=-N -l" -ldflags ${LDFLAGS} -o $(SYSMGR_BUILDDIR)/sysbox-mgr

sysbox-mgr-debug: $(SYSMGR_BUILDDIR)/$(SYSMGR_DEBUG_TARGET)

sysbox-mgr-static: $(SYSMGR_BUILDDIR)/$(SYSFS_STATIC_TARGET)

$(SYSMGR_BUILDDIR)/$(SYSFS_STATIC_TARGET): $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC) $(LIBDOCKER_SRC)
	$(GO_XCOMPILE) CGO_ENABLED=1 $(GO) build -tags "netgo osusergo static_build" \
		-installsuffix netgo -ldflags "-w -extldflags -static" -ldflags ${LDFLAGS} \
		-o $(SYSMGR_BUILDDIR)/sysbox-mgr

lint:
	$(GO) vet $(allpackages)
	$(GO) fmt $(allpackages)

listpackages:
	@echo $(allpackages)

clean:
	rm -f $(SYSMGR_BUILDDIR)/sysbox-mgr

distclean: clean
	rm -rf $(SYSFS_BUILDROOT)

# memoize allpackages, so that it's executed only once and only if used
_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)
