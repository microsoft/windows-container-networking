# Source files common to all targets.
COREFILES = \
	$(wildcard common/*.go) \
	$(wildcard network/*.go) \

# Source files for building CNI plugin.
CNIFILES = \
	$(wildcard cni/*.go) \
	$(wildcard cni/network/*.go) \
	$(wildcard cni/network/plugin/*.go) \
	$(COREFILES)

CNI_NET_DIR = cni/network/plugin
OUTPUTDIR = out

# Containerized build parameters.
BUILD_CONTAINER_IMAGE = wcn-build
BUILD_CONTAINER_NAME = wcn-builder
BUILD_CONTAINER_REPO_PATH = /go/src/github.com/microsoft/windowscontainernetworking
BUILD_USER ?= $(shell id -u)

# Docker plugin image parameters.

VERSION ?= $(shell git describe --tags --always --dirty)

ENSURE_OUTPUTDIR_EXISTS := $(shell mkdir -p $(OUTPUTDIR))

# Shorthand target names for convenience.
wincni.exe: $(OUTPUTDIR)/wincni.exe
all: wincni.exe

# Clean all build artifacts.
.PHONY: clean
clean:
	rm -rf $(OUTPUTDIR)

# Build the Windows CNI IPAM plugin for windows_amd64.
$(OUTPUTDIR)/wincni.exe: $(CNIFILES)
	GOOS=windows GOARCH=amd64 go build -v -o $(OUTPUTDIR)/wincni.exe -ldflags "-X main.version=$(VERSION) -s -w" $(CNI_NET_DIR)/*.go
