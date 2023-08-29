# Windows Container Networking CNI
[![Go Report Card](https://goreportcard.com/badge/github.com/Microsoft/windows-container-networking)](https://goreportcard.com/report/github.com/Microsoft/windows-container-networking)

## Overview
This repo contains plugins meant for testing/development of latest windows features. Their primary use case right now is with a CRI and containerd

## CNI Plugins Available
* `sdnoverlay`
* `nat`
* `sdnbridge`

## Releases
Create a checkpoint for a release using tags

`git tag -a v0.3.1 -m "includes intent-based cni config generation script"`

`git push origin v0.3.1`



The below make command creates a sha signed package under the release directory.

`make release`


These packages need to be uploaded manually while publishing a release from GitHub portal.

To publish a release, go to the [Releases](https://github.com/microsoft/windows-container-networking/releases) section in the portal, and click on 'Draft a new release'. 

Choose the tag created, and upload the packages. Make sure to add context about the release and list down the major changes. Hit 'Publish Release' and you are done.


* ToDo: Automated Release

## Build
These plugins are made for windows and need to be compiled for windows. However, you can cross-compile them from Linux.

If you have make installed on your system:

`make all` - will build all plugins: `nat.exe`, `sdnbridge.exe`, and `sdnoverlay.exe`
`make <plugin>` - will build an individual plugin

Else:

`GOOS=windows GOARCH=amd64 go build -v -o out/<plugin>.exe plugins/<plugin>/*.go`

### Building inside a Linux container

On a Linux machine, run `make dev`, then `make all`. That will cross-build the Windows binaries in a clean environment.

## Testing
There is a test suite that should be run (`make test`) before any changes. Opening a PR should trigger a Jenkins run that will run all the tests. If you wish to run them locally, you'll need a nanoserver image pulled from docker. 

Currently there are two groups of end-to-end tests shared by all the plugins

* Properties Verification - tests an add command and verifies that the resulting state is as expected. I.e. we attach an endpoint that endpoint has policy x,y,z etc. 
* Connectivity Testing -  creates a container and makes a CNI call for it and verifies that the container has connectivity for pod-to-pod, host-to-pod, pod-to-host, and pod-to-internet

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

## Code of Conduct
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
