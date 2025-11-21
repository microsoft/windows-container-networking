# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.3.2] - 2025-11-21

### Changed
- Updated Go version to 1.21.1 (#121)

### Fixed
- Fixed release pipeline to preserve 'v' prefix in artifact names (#120)
- Ensure CNI only adds default routes with a valid (non-empty) gateway (#116)
- Map CNI config 'type' to correct HCN NetworkType constant (#99)

### Security
- Bump golang.org/x/net from 0.8.0 to 0.33.0 (#111)

## [v0.3.1] - 2024-08-16

### Changed
- Bump up hcsshim version to 0.8.26 (#106)

### Added
- Intent-based CNI config generation script

## [v0.3.0] - 2024-07-01

### Added
- CNI config 1.0.0 support (#101)
- Additional validations for DHCP enabled container host (#102)

### Fixed
- Handle nil pointer if network not created (#82)

### Changed
- Updated issue templates (#88)
- Added GitHub-based workflows for testing and releases (#86)

## [v0.2.2]

### Fixed
- Additional validations for DHCP enabled container host

### Testing
- Removed outdated hcsshim/test dependency (#95)
- Properly detect gateway interface in L2Bridge tests (#97)
- Enable Unit Tests (#94)

### Quality
- Update code for golangci-lint and run `go fmt` (#87)

## [v0.2.1]

### Changed
- Initial changelog tracking

[Unreleased]: https://github.com/microsoft/windows-container-networking/compare/v0.3.2...HEAD
[v0.3.2]: https://github.com/microsoft/windows-container-networking/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/microsoft/windows-container-networking/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/microsoft/windows-container-networking/compare/v0.2.2...v0.3.0
[v0.2.2]: https://github.com/microsoft/windows-container-networking/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/microsoft/windows-container-networking/releases/tag/v0.2.1
