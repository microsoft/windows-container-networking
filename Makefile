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
# Based on Azure/aks-engine Makefile
REPO_PATH := github.com/Microsoft/windows-container-networking
DEV_ENV_IMAGE := quay.io/deis/go-dev:v1.19.1
DEV_ENV_WORK_DIR := /go/src/${REPO_PATH}
DEV_ENV_OPTS := --rm -v ${CURDIR}:${DEV_ENV_WORK_DIR} -w ${DEV_ENV_WORK_DIR} ${DEV_ENV_VARS}
DEV_ENV_CMD := docker run ${DEV_ENV_OPTS} ${DEV_ENV_IMAGE}
DEV_ENV_CMD_IT := docker run -it ${DEV_ENV_OPTS} ${DEV_ENV_IMAGE}
DEV_CMD_RUN := docker run ${DEV_ENV_OPTS}

# Docker plugin image parameters.

VERSION ?= $(shell git describe --tags --always --dirty)

ENSURE_OUTPUTDIR_EXISTS := $(shell mkdir -p $(OUTPUTDIR))

# Shorthand target names for convenience.
sdnbridge: $(OUTPUTDIR)/sdnbridge
sdnoverlay: $(OUTPUTDIR)/sdnoverlay
nat: $(OUTPUTDIR)/nat
all: sdnbridge sdnoverlay nat

# Containerized Build Environment
.PHONY: dev
dev:
	$(DEV_ENV_CMD_IT) bash


# Clean all build artifacts.
.PHONY: clean
clean:
	rm -rf $(OUTPUTDIR)

$(OUTPUTDIR)/sdnbridge $(OUTPUTDIR)/sdnoverlay $(OUTPUTDIR)/nat : $(CNIFILES)
	GOOS=windows GOARCH=amd64 go build -v -o $(OUTPUTDIR)/$(subst $(OUTPUTDIR)/,,$@).exe -ldflags "-X main.version=$(VERSION) -s -w" $(CNI_NET_DIR)/$(subst $(OUTPUTDIR)/,,$@)/*.go

.PHONY: test
test :
	GOOS=windows GOARCH=amd64 go test -v ./...
