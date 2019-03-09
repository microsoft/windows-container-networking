# Windows Container Networking CNI
[![Go Report Card](https://goreportcard.com/badge/github.com/Microsoft/windows-container-networking)]
(https://goreportcard.com/report/github.com/Microsoft/windows-container-networking)

## Overview
This repo contains plugins meant for testing/development of latest windows features. Their primary use case right now is with a CRI and containerd

## CNI Plugins Available
* `sdnoverlay`
* `nat`
* `sdnbridge`

## Releases
Currently you must build the binaries yourself (see below)

* ToDo: Automated Release

## Build
These plugins are made for windows and need to be compiled for windows

If you have make installed on your system:

`make all` \ `make <plugin>`

Else:

`GOOS=windows GOARCH=amd64 go build -v -o out/<plugin>.exe plugins/<plugin>/*.go` 

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