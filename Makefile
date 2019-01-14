# Source files common to all targets.
COREFILES = \
	$(wildcard common/*.go) \
	$(wildcard network/*.go) \

# Source files for building CNI plugin.
CNIFILES = \
	$(wildcard cni/*.go) \
	$(wildcard cni/network/*.go) \
	$(wildcard plugins/*.go) \
	$(COREFILES)

CNI_NET_DIR = plugins
OUTPUTDIR = out

# Containerized build parameters.
BUILD_CONTAINER_IMAGE = wcn-build
BUILD_CONTAINER_NAME = wcn-builder
BUILD_CONTAINER_REPO_PATH = /go/src/github.com
BUILD_USER ?= $(shell id -u)

# Docker plugin image parameters.

VERSION ?= $(shell git describe --tags --always --dirty)

ENSURE_OUTPUTDIR_EXISTS := $(shell mkdir -p $(OUTPUTDIR))

# Shorthand target names for convenience.
sdnbridge: $(OUTPUTDIR)/sdnbridge
sdnoverlay: $(OUTPUTDIR)/sdnoverlay
nat: $(OUTPUTDIR)/nat
all: sdnbridge sdnoverlay nat

# Clean all build artifacts.
.PHONY: clean
clean:
	rm -rf $(OUTPUTDIR)

$(OUTPUTDIR)/sdnbridge $(OUTPUTDIR)/sdnoverlay $(OUTPUTDIR)/nat : $(CNIFILES)
	GOOS=windows GOARCH=amd64 go build -v -o $(OUTPUTDIR)/$(subst $(OUTPUTDIR)/,,$@).exe -ldflags "-X main.version=$(VERSION) -s -w" $(CNI_NET_DIR)/$(subst $(OUTPUTDIR)/,,$@)/*.go
