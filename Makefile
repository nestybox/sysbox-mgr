#
# sysbox-mgr Makefile
#
# Note: targets must execute from the $SYSMGR_DIR

.PHONY: clean sysbox-mgr-debug sysbox-mgr-static lint list-packages

GO := go

SYSMGR_BUILDROOT := build
SYSMGR_BUILDDIR := $(SYSMGR_BUILDROOT)/$(TARGET_ARCH)
SYSMGR_TARGET := sysbox-mgr
SYSMGR_DEBUG_TARGET := sysbox-mgr-debug
SYSMGR_STATIC_TARGET := sysbox-mgr-static
SYSMGR_DIR := $(CURDIR)
SYSMGR_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

SYSMGR_GRPC_DIR := ../sysbox-ipc/sysboxMgrGrpc
SYSMGR_GRPC_SRC := $(shell find $(SYSMGR_GRPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

SYSLIB_DIR := ../sysbox-libs
SYSLIB_SRC := $(shell find $(SYSLIB_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_NO)-dirty,$(COMMIT_NO))
BUILT_AT := $(shell date)
BUILT_BY := $(shell git config user.name)

LDFLAGS := -X 'main.edition=${EDITION}' -X main.version=${VERSION} \
		-X main.commitId=$(COMMIT) -X 'main.builtAt=$(BUILT_AT)' \
		-X 'main.builtBy=$(BUILT_BY)'

# idmapped mount is supported in kernels >= 5.12
KERNEL_REL := $(shell uname -r)
KERNEL_REL_MAJ := $(shell echo $(KERNEL_REL) | cut -d'.' -f1)
KERNEL_REL_MIN := $(shell echo $(KERNEL_REL) | cut -d'.' -f2)

ifeq ($(shell test $(KERNEL_REL_MAJ) -gt 5; echo $$?),0)
	IDMAPPED_MNT := 1
endif

ifeq ($(shell test $(KERNEL_REL_MAJ) -eq 5; echo $$?),0)
	ifeq ($(shell test $(KERNEL_REL_MIN) -ge 12; echo $$?),0)
		IDMAPPED_MNT := 1
	endif
endif

ifeq ($(IDMAPPED_MNT),1)
	BUILDTAGS ?= idmapped_mnt
endif

# Set cross-compilation flags if applicable.
ifneq ($(SYS_ARCH),$(TARGET_ARCH))
	ifeq ($(TARGET_ARCH),armel)
		GO_XCOMPILE := CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 CC=arm-linux-gnueabi-gcc
	else ifeq ($(TARGET_ARCH),armhf)
		GO_XCOMPILE := CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc
	else ifeq ($(TARGET_ARCH),arm64)
		GO_XCOMPILE = CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc
	else ifeq ($(TARGET_ARCH),amd64)
		GO_XCOMPILE = CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-gnu-gcc
	endif
endif

.DEFAULT: sysbox-mgr

sysbox-mgr: $(SYSMGR_BUILDDIR)/$(SYSMGR_TARGET)

$(SYSMGR_BUILDDIR)/$(SYSMGR_TARGET): $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC) $(SYSLIB_SRC)
	$(GO_XCOMPILE) $(GO) build -buildvcs=false -trimpath -tags "$(BUILDTAGS)" -ldflags "${LDFLAGS}" -o $(SYSMGR_BUILDDIR)/sysbox-mgr

sysbox-mgr-debug: $(SYSMGR_BUILDDIR)/$(SYSMGR_DEBUG_TARGET)

$(SYSMGR_BUILDDIR)/$(SYSMGR_DEBUG_TARGET): $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC) $(SYSLIB_SRC)
	$(GO_XCOMPILE) $(GO) build -buildvcs=false -trimpath -tags "$(BUILDTAGS)" -gcflags="all=-N -l" -ldflags "${LDFLAGS}" \
		-o $(SYSMGR_BUILDDIR)/sysbox-mgr

sysbox-mgr-static: $(SYSMGR_BUILDDIR)/$(SYSMGR_STATIC_TARGET)

$(SYSMGR_BUILDDIR)/$(SYSMGR_STATIC_TARGET): $(SYSMGR_SRC) $(SYSMGR_GRPC_SRC) $(SYSLIB_SRC)
	CGO_ENABLED=1 $(GO_XCOMPILE) $(GO) build -buildvcs=false -trimpath -tags "$(BUILDTAGS) netgo osusergo" \
		-installsuffix netgo -ldflags "-w -extldflags -static ${LDFLAGS}" \
		-o $(SYSMGR_BUILDDIR)/sysbox-mgr

gomod-tidy:
	$(GO) mod tidy

lint:
	$(GO) vet $(allpackages)
	$(GO) fmt $(allpackages)

listpackages:
	@echo $(allpackages)

clean:
	rm -f $(SYSMGR_BUILDDIR)/sysbox-mgr

distclean: clean
	rm -rf $(SYSMGR_BUILDROOT)

# memoize allpackages, so that it's executed only once and only if used
_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)
