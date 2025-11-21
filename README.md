# Windows Container Networking CNI
[![Go Report Card](https://goreportcard.com/badge/github.com/Microsoft/windows-container-networking)](https://goreportcard.com/report/github.com/Microsoft/windows-container-networking)
[![CI](https://github.com/microsoft/windows-container-networking/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/windows-container-networking/actions/workflows/ci.yml)
[![CodeQL](https://github.com/microsoft/windows-container-networking/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/microsoft/windows-container-networking/actions/workflows/github-code-scanning/codeql)

## Overview
This repo contains plugins meant for testing/development of latest windows features. Their primary use case right now is with a CRI and containerd

## CNI Plugins Available
* `sdnoverlay`
* `nat`
* `sdnbridge`

## Releases

### Creating a New Release

Releases are fully automated via GitHub Actions. To create a new release:

1. **Ensure all changes are committed and tests pass:**
   ```bash
   make test
   ```

2. **Update CHANGELOG.md** with the new version and changes

3. **Create a GPG-signed annotated tag:**
   ```bash
   git tag -s v0.x.x -m "Release v0.x.x

   Brief description of changes.
   See CHANGELOG.md for full details."
   ```
   
   **Important:** Always use GPG-signed tags (`-s` flag) for releases. This ensures authenticity and prevents tampering.

4. **Push the tag:**
   ```bash
   git push origin v0.x.x
   ```

5. **Monitor the release:** The [GitHub Actions workflow](https://github.com/microsoft/windows-container-networking/actions) will automatically:
   - Build binaries for all platforms
   - Run CI tests
   - Generate SHA256/SHA512 checksums
   - Create and publish the GitHub release

### Release Artifacts

Each release includes:
- `windows-container-networking-cni-amd64-v0.x.x.zip` - Binary package
- `windows-container-networking-cni-amd64-v0.x.x.zip.sha256` - SHA256 checksum
- `windows-container-networking-cni-amd64-v0.x.x.zip.sha512` - SHA512 checksum

### Security Policy

- **Never modify published releases** - If there's an issue, create a new patch version
- **Always use GPG-signed tags** - Ensures release authenticity
- **Verify checksums** - All artifacts include cryptographic checksums
- **Tag format** - Always use `vMAJOR.MINOR.PATCH` format (e.g., `v0.3.2`)

See [CHANGELOG.md](CHANGELOG.md) for release history.

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
