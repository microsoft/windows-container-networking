module github.com/Microsoft/windows-container-networking

go 1.21.1

require (
	github.com/Microsoft/go-winio v0.5.2
	github.com/Microsoft/hcsshim v0.8.26
	github.com/containerd/go-runc v1.0.0
	github.com/containernetworking/cni v1.1.2
	github.com/opencontainers/runtime-tools v0.0.0-20190313075039-7125f1d443b0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/sync v0.10.0
)

require (
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/containerd/cgroups v1.0.3 // indirect
	github.com/containerd/console v1.0.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417 // indirect
	github.com/opencontainers/selinux v1.10.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.1.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.1.5
	golang.org/x/sys => golang.org/x/sys v0.1.0
)
