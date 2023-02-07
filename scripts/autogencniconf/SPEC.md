# CNI Configuration Autogen Tool Specification
- [CNI Configuration Autogen Tool Specification](#cni-configuration-autogen-tool-specification)
  - [Version](#version)
      - [Released versions](#released-versions)
  - [Overview](#overview)
  - [Summary](#summary)
  - [Section 1: Autogen configuration format](#section-1-autogen-configuration-format)
    - [Configuration format](#configuration-format)
  - [Section 2: Required Parameters](#section-2-required-parameters)
    - [Overview](#overview-1)
    - [Parameters](#parameters)
  - [Section 3: Optional Parameters](#section-3-optional-parameters)
    - [Overview](#overview-2)
    - [Parameters](#parameters-1)
  - [Section 4: Additional Parameters](#section-4-additional-parameters)
    - [Overview](#overview-3)
    - [Parameters](#parameters-2)
  - [Appendix: Examples](#appendix-examples)
    - [Basic Conf](#basic-conf)
    - [Conf with additional policies](#conf-with-additional-policies)

## Version

This is CNI Conf Autogen Tool **spec** version **1.0.0**.

Note that this is **independent from the version of the CNI library, plugins and container runtimes** ).

#### Released versions

Released versions of the spec are available as Git tags.

| tag                                                                                  | spec permalink                                                                        | major changes                     |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- | --------------------------------- |
| [`spec-v1.0.0`](https://github.com/microsoft/windows-container-networking/cni/releases/tag/spec-v1.0.0) | [spec at v1.0.0](https://github.com/microsoft/windows-container-networking/cni/blob/spec-v1.0.0/SPEC.md) | Removed non-list configurations; removed `version` field of `interfaces` array |

*Do not rely on these tags being stable.  In the future, we may change our mind about which particular commit is the right marker for a given historical spec version.*


## Overview

This document aims to specify the interface between "any client using the autogen cni conf tool" and the "tool itself". The key words "must", "must not", "required", "shall", "shall not", "should", "should not", "recommended", "may" and "optional" are used as specified in [RFC 2119][rfc-2119].

## Summary

The autogen CNI Configuration specification defines a format for users to define intent-based cni configuration via a json string. The autogen tool takes care of interpreting the intent-based cni configuration to a [spec](https://github.com/containernetworking/cni/edit/main/SPEC.md) compliant CNI configuration.

## Section 1: Autogen configuration format
### Configuration format
The tool expects following mandatory arguments:

- `CniConfPath` (string): File path where the CNI configuration would be generated.
- `CniArgs` (string): Base64 encoded JSON string which defines the intent-based CNI configuration.

Below sections specify the JSON format that needs to be passed after [encoding](https://www.base64encode.org/) it in Base64 ASCII format. [Ensure](https://jsonlint.com/) the json formatting is correct before encoding.

#### Autogen CNI configuration objects:
Autogen CNI configuration objects may contain additional fields than the ones defined here.

**Required keys:**
- `Name` (string): Matches the name of the CNI plugin binary on disk. Must not contain characters disallowed in file paths for the system (e.g. / or \\).
- `Type` (string): Matches the type of the CNI plugin binary on disk. (L2Bridge/L2Tunnel/NAT)

Detailed in [section 2](#section-2-required-parameters).

Optional Keys:**
- `DnsServer` (string): IP Address of the DNS Server.
- `Gateway` (string): IP Address of the Gateway for the endpoint.
 
 Defined in [section 3](#section-3-optional-parameters).

**Additional keys, platform-specific:**
- `Subnet` (string): CIDR of the network corresponding to endpoint.
- `LocalEndpoint` (string): IP Address of the local endpoint. Used to configure default ACL policies for the endpoint.
- `InfraPrefix` (string): CIDR of the underlying infra network. Used to configure default ACL policies for the network.
- `AddditionalPolicies` (dictionary): Defined in [section 4](#section-4-additional-parameters).

#### [Example configuration](#appendix-examples)

## Section 2: Required Parameters
### Overview
### Parameters
## Section 3: Optional Parameters
### Overview
### Parameters
## Section 4: Additional Parameters
### Overview
### Parameters
## Appendix: Examples
### Basic Conf
```jsonc
{
	"Name": "azure-cni",
	"Type": "L2Bridge",
	"Subnet": "192.168.0.0/24",
	"LocalEndpoint": "192.168.0.1",
	"InfraPrefix": "172.16.0.0/24",
	"Gateway": "192.168.0.2",
	"DnsServer": "8.8.8.8"
}
```
### Conf with additional policies
```jsonc
{
	"Name": "azure-cni",
	"Type": "L2Bridge",
	"Subnet": "192.168.0.0/24",
	"LocalEndpoint": "192.168.0.1",
	"InfraPrefix": "172.16.0.0/24",
	"Gateway": "192.168.0.2",
	"DnsServer": "8.8.8.8",
	"Policies": [{
			"Type": "ACL",
			"Value": {
				"RemoteAddresses": "192.168.0.122",
				"Remoteports": "8080",
				"Action": "Block",
				"Protocols": "6",
				"Direction": "Out",
				"Priority": 200
			}
		},
		{
			"Type": "ACL",
			"Value": {
				"Action": "Allow",
				"Direction": "Out",
				"Priority": 2000
			}
		}
	]
}
```
