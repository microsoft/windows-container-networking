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

GOCMD=go
GOLOCALENV=GO111MODULE=on GOARCH=amd64 GOOS=windows
GOBUILD=$(GOLOCALENV) $(GOCMD) build -v -mod=vendor
GOTEST=$(GOLOCALENV) $(GOCMD) test -v -p 1 -mod=vendor

CNI_NET_DIR = plugins
OUTPUTDIR = out

# Containerized build parameters.
# Based on Azure/aks-engine Makefile
REPO_PATH := github.com/Microsoft/windows-container-networking
DEV_ENV_IMAGE := golang:1.21
DEV_ENV_WORK_DIR := /go/src/${REPO_PATH}
DEV_ENV_OPTS := --rm -v ${CURDIR}:${DEV_ENV_WORK_DIR} -w ${DEV_ENV_WORK_DIR} ${DEV_ENV_VARS}
# Multi-stage Dockerfile that creates the final image from golang:1.21.1
container:
	docker build -f Dockerfile -t $(CONTAINER_IMAGE):$(CONTAINER_IMAGE_TAG) .
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
	rm -rf $(OUTPUTDIR) release vendor

$(OUTPUTDIR)/sdnbridge $(OUTPUTDIR)/sdnoverlay $(OUTPUTDIR)/nat : $(CNIFILES)
	$(GOBUILD) -o $(OUTPUTDIR)/$(subst $(OUTPUTDIR)/,,$@).exe -ldflags "-X main.version=$(VERSION) -s -w" $(CNI_NET_DIR)/$(subst $(OUTPUTDIR)/,,$@)/*.go

.PHONY: test
test :
	$(GOTEST) ./...

.PHONY : format
format :
	gofmt -s -l -w ./common/* ./cni/* ./network/* ./plugins/* ./test/*

.PHONY : vendor
vendor :
	go mod vendor

.PHONY : release
release : all
	mkdir -p release; \
	zip -jrmv release/windows-container-networking-cni-amd64-$(VERSION).zip out; \
	for file in ./release/*.zip ; do \
		echo "Generated release file: $$file"; \
		shasum -a 256 $$file > $$file.sha256; \
		shasum -a 512 $$file > $$file.sha512; \
	done
