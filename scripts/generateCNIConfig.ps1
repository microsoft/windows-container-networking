[CmdletBinding()]
param (
    [string]
    $CniConfPath = ".\cniConf"
)

enum OptionalKeysFlag {
    NoOptKeys = 1
    Master = 2 #[OptionalKeysFlag]::NoOptKeys -shl 1
    Capabilities = 4 #[OptionalKeysFlag]::NoOptKeys -shl 2
    MaxFlags = 8 #[OptionalKeysFlag]::NoOptKeys -shl 3
}

enum WKOptionalKeysFlag {
    NoWKOptKeys = 1
    Ipam = 2 #[WKOptionalKeysFlag]::NoWKOptKeys -shl 1
    Dns = 4 #[WKOptionalKeysFlag]::NoWKOptKeys -shl 2
    MaxFlags = 8 #[WKOptionalKeysFlag]::NoWKOptKeys -shl 3
}

class CniConf {
    [System.Collections.Specialized.OrderedDictionary] $CniBase
    [uint16] $OptKeyParams
    [uint16] $WKOptKeyParams

    CniConf() {
        $this.CniBase = [System.Collections.Specialized.OrderedDictionary]::new()
        # Set optional fields to be populated
        $this.OptKeyParams = $this.OptKeyParams -bor [OptionalKeysFlag]::Capabilities -bor [OptionalKeysFlag]::Master
        # Set wellknown optional fields to be populated
        $this.WKOptKeyParams = $this.WKOptKeyParams -bor [WKOptionalKeysFlag]::Dns -bor [WKOptionalKeysFlag]::Ipam
    }

    Populate() {
        $this.PopulateRequiredKeys()
        $this.PopulateOptionalKeys()
        $this.PopulateWellKnownOptKeys();
        $this.PopulateOtherKeys();
    }

    PopulateRequiredKeys() {
        $this.CniBase.Add('cniVersion', '0.2.0')
        $this.CniBase.Add('name', 'cni1') #TODO: Parameterize
        $this.CniBase.Add('type', 'L2Bridge') #ToDO: Parameterize
    }

    PopulateOptionalKeys() {
       for ($flag = ([OptionalKeysFlag]::NoOptKeys).value__; $flag -le [OptionalKeysFlag]::MaxFlags; $flag = $flag -shl 1) {
            switch(($flag -band $this.OptKeyParams)) {

                ([OptionalKeysFlag]::Capabilities).value__ {
                    $capa = [System.Collections.Specialized.OrderedDictionary]::new()
                    $capa.Add('portMappings', $true)
                    $capa.Add('dns', $true)

                    $this.CniBase.Add('capabilities', $capa)
                }

                ([OptionalKeysFlag]::Master).value__ {
                    $this.CniBase.Add('master', 'External')
                }
            }
       } 
    }

    PopulateWellKnownOptKeys() {
       for ($flag = ([WKOptionalKeysFlag]::NoWKOptKeys).value__; $flag -le [WKOptionalKeysFlag]::MaxFlags; $flag = $flag -shl 1) {
            switch(($flag -band $this.WKOptKeyParams)) {

                ([WKOptionalKeysFlag]::Ipam).value__ {
                    $ipamFields = [System.Collections.Specialized.OrderedDictionary]::new()
                    $ipamFields.Add('environment', 'azure')
                    $ipamFields.Add('subnet', '192.168.0.0/24') # TODO: Parameterize Subnet
                    $routes = @()
                    $routes += (@{'GW'='192.168.0.2';}) # TODO: Parameterize
                    $ipamFields.Add('routes', $routes)

                    $this.CniBase.Add('ipam', $ipamFields)
                }

                ([WKOptionalKeysFlag]::Dns).value__ {
                    $dnsFields = [System.Collections.Specialized.OrderedDictionary]::new()
                    $nameservers = @()
                    $nameservers += ('8.8.8.8') #TODO: Parameterize
                    $search = @()
                    $search += ('svc.cluster.local')
                    $dnsFields.Add('Nameservers', $nameservers)
                    $dnsFields.Add('Search', $search)
                    $this.CniBase.Add('dns', $dnsFields)
                }
            }
       } 
    }

    PopulateOtherKeys() {
        $optionalFlags = [System.Collections.Specialized.OrderedDictionary]::new()
        $optionalFlags.Add('localRoutedPortMapping', $true)
        $optionalFlags.Add('allowAclPortMapping', $true)
        $this.CniBase.Add('optionalFlags', $optionalFlags)

        $additionalArgs = @()
        $additionalArgs += $this.PopulateDefaultpolicies()

        # Populate user defined policies
        $this.CniBase.Add('AdditionalArgs', $additionalArgs)
    }

    [PSCustomObject[]] PopulateDefaultpolicies() {
        $defaultPolicies = @()
        $outboundpolicy = [System.Collections.Specialized.OrderedDictionary]::new()
        $exceptions = @()
        $exceptions += ('192.168.0.0/24') #TODO: Parameterize Subnet
        $exceptions += ('192.168.0.101') #TODO: Parameterize LocalEndpoint

        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'OutBoundNAT')
        $value.Add('Settings', @{'Exceptions' = $exceptions})
        $outboundPolicy.Add('Name', 'EndpointPolicy')
        $outboundPolicy.Add('Value', $value)
        $defaultPolicies += $outboundpolicy

        $aclPolicy1 = [System.Collections.Specialized.OrderedDictionary]::new()
        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'ACL')
        $value.Add('Settings', [ordered]@{
                                'Action' = 'Allow';
                                'Protocols' = '6';
                                'LocalPorts' = '1111';
                                'Direction' = 'In';
                                'Priority' = 101;
                                })
        $aclPolicy1.Add('Name', 'EndpointPolicy')
        $aclPolicy1.Add('Value', $value)
        $defaultPolicies += $aclPolicy1

        $aclPolicy2 = [System.Collections.Specialized.OrderedDictionary]::new()
        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'ACL')
        $value.Add('Settings', [ordered]@{
                                'RemoteAddresses' = '192.168.0.101'; #TODO: Parameterize LocalEndpoint
                                'Remoteports' = '31002';
                                'Action' = 'Allow';
                                'Protocols' = '6';
                                'Direction' = 'Out';
                                'Priority' = 200;
                                })
        $aclPolicy2.Add('Name', 'EndpointPolicy')
        $aclPolicy2.Add('Value', $value)
        $defaultPolicies += $aclPolicy2

        $aclPolicy3 = [System.Collections.Specialized.OrderedDictionary]::new()
        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'ACL')
        $value.Add('Settings', [ordered]@{
                                'RemoteAddresses' = '192.168.0.120'; #TODO: Parameterize InfraPrefix
                                'Action' = 'Block';
                                'Direction' = 'Out';
                                'Priority' = 1998;
                                })
        $aclPolicy3.Add('Name', 'EndpointPolicy')
        $aclPolicy3.Add('Value', $value)
        $defaultPolicies += $aclPolicy3

        $aclPolicy4 = [System.Collections.Specialized.OrderedDictionary]::new()
        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'ACL')
        $value.Add('Settings', [ordered]@{
                                'RemoteAddresses' = '192.168.0.0/24'; #TODO: Parameterize Subnet
                                'Action' = 'Block';
                                'Direction' = 'Out';
                                'Priority' = 1999;
                                })
        $aclPolicy4.Add('Name', 'EndpointPolicy')
        $aclPolicy4.Add('Value', $value)
        $defaultPolicies += $aclPolicy4

        $aclPolicy5 = [System.Collections.Specialized.OrderedDictionary]::new()
        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'ACL')
        $value.Add('Settings', [ordered]@{
                                'Action' = 'Allow';
                                'Direction' = 'Out';
                                'Priority' = 2000;
                                })
        $aclPolicy5.Add('Name', 'EndpointPolicy')
        $aclPolicy5.Add('Value', $value)
        $defaultPolicies += $aclPolicy5

        return $defaultPolicies
    }

    [String]Get() {
        $cniConfString += ConvertTo-Json -Depth 50 $this.CniBase
        return $cniConfString
    }
}

######### Main #########
$cniConfObj = [CniConf]::new()
$cniConfObj.Populate() 
$cniConfObj.Get() | Out-File -FilePath $CniConfPath -Encoding ascii
