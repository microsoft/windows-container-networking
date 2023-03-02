# CNI Configuration Autogen Tool Specification
- [CNI Configuration Autogen Tool Specification](#cni-configuration-autogen-tool-specification)
  - [Version](#version)
      - [Released versions](#released-versions)
  - [Overview](#overview)
  - [Summary](#summary)
  - [Section 1: Autogen configuration format](#section-1-autogen-configuration-format)
    - [Configuration format](#configuration-format)
  - [Section 2: Required Parameters](#section-2-required-parameters)
  - [Section 3: WellKnown Parameters](#section-3-wellknown-parameters)
  - [Section 4: Additional Parameters](#section-4-additional-parameters)
    - [Additional Policies](#configure-additional-policies)
      - [ACL Policy](#acl-policy)
      - [OutBound NAT Policy](#outbound-nat-policy)
      - [SDNRoute Policy](#sdnroute-policy)
  - [Appendix: Examples](#appendix-examples)
    - [Basic Conf](#basic-conf)
    - [Conf with additional policies](#conf-with-additional-policies)
	- [Sample auto-generated CNI configuration](#sample-auto-generated-cni-configuration)

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
The tool expects following arguments:

- `CniConfPath` (string): File path where the CNI configuration would be generated. This parameter is *NOT MANDATORY*, by default the cni conf will be generated in the directory from which the script is invoked.
- `CniArgs` (string): Base64 encoded JSON string which defines the intent-based CNI configuration. This parameter is *MANDATORY*. Check out the below sample invocation for a refernce to a base64 encoded json string.
- `Version` (string): This is the version of the autogen tool. This parameter is *NOT MANDATORY*, by default the script will invoke the base version of 1.0.0.

Sample invocation:

```ps
.\generateCNIConfig.ps1 -CniArgs "ew0KCSJOYW1lIjogImF6dXJlLWNuaSIsDQoJIlR5cGUiOiAiTDJCcmlkZ2UiLA0KCSJTdWJuZXQiOiAiMTkyLjE2OC4wLjAvMjQiLA0KCSJMb2NhbEVuZHBvaW50IjogIjE5Mi4xNjguMC4xIiwNCgkiSW5mcmFQcmVmaXgiOiAiMTcyLjE2LjAuMC8yNCIsDQoJIkdhdGV3YXkiOiAiMTkyLjE2OC4wLjIiLA0KCSJEbnNTZXJ2ZXIiOiAiOC44LjguOCIsDQoJIlBvbGljaWVzIjogW3sNCgkJCSJUeXBlIjogIkFDTCIsDQoJCQkiU2V0dGluZ3MiOiB7DQoJCQkJIlJlbW90ZUFkZHJlc3NlcyI6ICIxOTIuMTY4LjAuMTIyIiwNCgkJCQkiUmVtb3RlcG9ydHMiOiAiODA4MCIsDQoJCQkJIkFjdGlvbiI6ICJCbG9jayIsDQoJCQkJIlByb3RvY29scyI6ICI2IiwNCgkJCQkiRGlyZWN0aW9uIjogIk91dCIsDQoJCQkJIlByaW9yaXR5IjogMjAwDQoJCQl9DQoJCX0sDQoJCXsNCgkJCSJUeXBlIjogIkFDTCIsDQoJCQkiU2V0dGluZ3MiOiB7DQoJCQkJIkFjdGlvbiI6ICJBbGxvdyIsDQoJCQkJIkRpcmVjdGlvbiI6ICJPdXQiLA0KCQkJCSJQcmlvcml0eSI6IDIwMDANCgkJCX0NCgkJfSwNCiAgICAgICAgew0KICAgICAgICAgICAgIlR5cGUiOiAiU0ROUm91dGUiLA0KICAgICAgICAgICAgIlNldHRpbmdzIjogew0KICAgICAgICAgICAgICAgICJEZXN0aW5hdGlvblByZWZpeCI6ICIxMC4wLjAuMC84IiwNCiAgICAgICAgICAgICAgICAiTmVlZEVuY2FwIjogdHJ1ZQ0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQoJXQ0KfQ=="
```

Below sections specify the JSON format that needs to be passed after [encoding](https://www.base64encode.org/) it in Base64 ASCII format. [Ensure](https://jsonlint.com/) the json formatting is correct before encoding.

#### [Example configuration](#appendix-examples)

## Section 2: Required Parameters
**Required keys:**
- `Name` (string): Matches the name of the CNI plugin binary on disk. Must not contain characters disallowed in file paths for the system (e.g. / or \\). This parameter is *MANDATORY*.
- `Type` (string): Matches the type of the CNI plugin binary on disk (L2Bridge/L2Tunnel/NAT). This parameter is *MANDATORY*.
## Section 3: WellKnown Parameters
**WellKnown Keys:**
- `Version` (string): CNI version. This parameter is *NOT MANDATORY*, defaults to version '0.2.0'.
- `DnsServers` (string[]): IP Addresses of the DNS NameServers. This parameter is *MANDATORY*.
- `Gateway` (string): IP Address of the Gateway for the endpoint. This parameter is *MANDATORY*.
## Section 4: Additional Parameters
**Additional keys, platform-specific:**
- `Subnet` (string): CIDR of the network corresponding to endpoint or POD subnet. Used to configure default policies for the endpoint.This parameter is *MANDATORY*.
- `LocalEndpoint` (string): IP Address of the local endpoint. Used to configure default policies for the endpoint. This parameter is *MANDATORY*.
- `InfraPrefix` (string): CIDR of the management network of the underlying node. Used to configure default policies for the network. This parameter is *MANDATORY*.
- `AddditionalPolicies` (dictionary): Defined [here](#configure-additional-policies). This parameter is *NOT MANDATORY*.
### Configure Additional Policies
#### ACL Policy
There are few system-defined default ACL policies. Users can configure additional ACL polices with below parameters.
- `RemoteAddresses` (string): This parameter is *NOT MANDATORY*.
- `RemotePorts` (string): This parameter is *NOT MANDATORY*.
- `Localports` (string): This parameter is *NOT MANDATORY*.
- `Action` (string): This parameter is *MANDATORY*.
- `Protocols` (string): This parameter is *NOT MANDATORY*.
- `Direction` (string): This parameter is *MANDATORY*.
- `RuleType` (string): This parameter is *NOT MANDATORY*.
- `Scope` (string): This parameter is *NOT MANDATORY*.
- `Priority` (integer): Relative priority of the rule. User defined policies *MUST HAVE* priorities between 100-4096.
#### OutBound NAT Policy
- `Exceptions` (string[]): List of IP Addresses/CIDRs to allow NATed outbound traffic. This parameter is *MANDATORY*.
#### SDNRoute Policy
- `DestinationPrefix` (string): .This parameter is *MANDATORY*.
- `NeedEncap` (bool): . This parameter is *MANDATORY*.
## Appendix: Examples
### Basic Conf
```jsonc
{
	"Name": "azure-cni",
	"Type": "sdnbridge",
	"Subnet": "192.168.0.0/24",
	"InfraPrefix": "172.16.0.0/24",
	"Gateway": "192.168.0.2",
	"DnsServers": "8.8.8.8"
}
```
### Conf with additional policies
```jsonc
{
	"Name": "azure-cni",
	"Type": "sdbridge",
    "Version": "0.3.0",
	"Subnet": "192.168.0.0/24",
	"InfraPrefix": "172.16.0.0/24",
	"Gateway": "192.168.0.2",
	"DnsServers": "8.8.8.8",
	"AdditionalPolicies": [{
			"Type": "ACL",
			"Settings": {
				"RemoteAddresses": "192.168.0.122",
				"Remoteports": "8080",
				"Action": "Block",
				"Protocols": "6",
				"Direction": "Out",
				"Priority": 2001
			}
		},
		{
			"Type": "ACL",
			"Settings": {
				"Action": "Allow",
				"Direction": "Out",
				"Priority": 2000
			}
		},
        {
            "Type": "SDNRoute",
            "Settings": {
                "DestinationPrefix": "10.0.0.0/8",
                "NeedEncap": true
            }
        }
	]
}
```
### Sample auto-generated CNI configuration
```jsonc
VERBOSE: Generated CNI conf: .\cni.conf
{
    "cniVersion":  "0.3.0",
    "name":  "azure-cni",
    "type":  "sdnbridge",
    "master":  "Ethernet",
    "capabilities":  {
                         "portMappings":  true,
                         "dns":  true
                     },
    "ipam":  {
                 "environment":  "azure",
                 "subnet":  "192.168.0.0/24",
                 "routes":  [
                                {
                                    "GW":  "192.168.0.2"
                                }
                            ]
             },
    "dns":  {
                "Nameservers":  [
                                    "8.8.8.8"
                                ],
                "Search":  [
                               "svc.cluster.local"
                           ]
            },
    "optionalFlags":  {
                          "localRoutedPortMapping":  true,
                          "allowAclPortMapping":  true
                      },
    "AdditionalArgs":  [
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "OutBoundNAT",
                                             "Settings":  {
                                                              "Exceptions":  [
                                                                                 "192.168.0.0/24",
                                                                                 "10.0.0.5/32"
                                                                             ]
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "SDNRoute",
                                             "Settings":  {
                                                              "DestinationPrefix":  "10.0.0.0/8",
                                                              "NeedEncap":  true
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Priority":  4999,
                                                              "Direction":  "Out",
                                                              "RemoteAddresses":  "168.63.129.16/32",
                                                              "Action":  "Block"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Priority":  5003,
                                                              "Direction":  "Out",
                                                              "RemoteAddresses":  "169.254.169.254/32",
                                                              "Action":  "Block"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "RemoteAddresses":  "192.168.0.122",
                                                              "Remoteports":  "8080",
                                                              "Action":  "Block",
                                                              "Protocols":  "6",
                                                              "Direction":  "Out",
                                                              "Priority":  2001
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Action":  "Allow",
                                                              "Direction":  "Out",
                                                              "Priority":  2000
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Priority":  5000,
                                                              "LocalPorts":  "1111",
                                                              "Protocols":  "6",
                                                              "Direction":  "In",
                                                              "Action":  "Allow"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Action":  "Allow",
                                                              "Direction":  "Out",
                                                              "RemotePorts":  "31002",
                                                              "RemoteAddresses":  "192.168.0.1",
                                                              "Priority":  5001,
                                                              "Protocols":  "6"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Action":  "Allow",
                                                              "Direction":  "Out",
                                                              "RemotePorts":  "53",
                                                              "RemoteAddresses":  "168.63.129.16/32",
                                                              "Priority":  5002,
                                                              "Protocols":  "6"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Action":  "Allow",
                                                              "Direction":  "Out",
                                                              "RemotePorts":  "53",
                                                              "RemoteAddresses":  "168.63.129.16/32",
                                                              "Priority":  5002,
                                                              "Protocols":  "17"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Priority":  6001,
                                                              "Direction":  "Out",
                                                              "RemoteAddresses":  "172.16.0.0/24",
                                                              "Action":  "Block"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Priority":  6002,
                                                              "Direction":  "Out",
                                                              "RemoteAddresses":  "192.168.0.0/24",
                                                              "Action":  "Block"
                                                          }
                                         }
                           },
                           {
                               "Name":  "EndpointPolicy",
                               "Value":  {
                                             "Type":  "ACL",
                                             "Settings":  {
                                                              "Priority":  6003,
                                                              "Direction":  "Out",
                                                              "Action":  "Allow"
                                                          }
                                         }
                           }
                       ]
}
```
