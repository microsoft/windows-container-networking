<#

This script generates CNI config from a Base64 encoded JSON string

Sample CNI Args:
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

Validate the json using JSON Lint (https://jsonlint.com/)

Encode the JSON string with ASCII as the destination character set (https://www.base64encode.org/)

Base64 Endoded string for above:
ew0KCSJOYW1lIjogImF6dXJlLWNuaSIsDQoJIlR5cGUiOiAiTDJCcmlkZ2UiLA0KCSJTdWJuZXQiOiAiMTkyLjE2OC4wLjAvMjQiLA0KCSJMb2NhbEVuZHBvaW50IjogIjE5Mi4xNjguMC4xIiwNCgkiSW5mcmFQcmVmaXgiOiAiMTcyLjE2LjAuMC8yNCIsDQoJIkdhdGV3YXkiOiAiMTkyLjE2OC4wLjIiLA0KCSJEbnNTZXJ2ZXIiOiAiOC44LjguOCIsDQoJIlBvbGljaWVzIjogW3sNCgkJCSJUeXBlIjogIkFDTCIsDQoJCQkiVmFsdWUiOiB7DQoJCQkJIlJlbW90ZUFkZHJlc3NlcyI6ICIxOTIuMTY4LjAuMTIyIiwNCgkJCQkiUmVtb3RlcG9ydHMiOiAiODA4MCIsDQoJCQkJIkFjdGlvbiI6ICJCbG9jayIsDQoJCQkJIlByb3RvY29scyI6ICI2IiwNCgkJCQkiRGlyZWN0aW9uIjogIk91dCIsDQoJCQkJIlByaW9yaXR5IjogMjAwDQoJCQl9DQoJCX0sDQoJCXsNCgkJCSJUeXBlIjogIkFDTCIsDQoJCQkiVmFsdWUiOiB7DQoJCQkJIkFjdGlvbiI6ICJBbGxvdyIsDQoJCQkJIkRpcmVjdGlvbiI6ICJPdXQiLA0KCQkJCSJQcmlvcml0eSI6IDIwMDANCgkJCX0NCgkJfQ0KCV0NCn0=

Report issues: containernetdev@microsoft.com

#>

[CmdletBinding()]

param (
    [string]
    $CniConfPath = ".\cniConf",

    [string]
    $CniArgs = "ew0KCSJOYW1lIjogImF6dXJlLWNuaSIsDQoJIlR5cGUiOiAiTDJCcmlkZ2UiLA0KCSJTdWJuZXQiOiAiMTkyLjE2OC4wLjAvMjQiLA0KCSJMb2NhbEVuZHBvaW50IjogIjE5Mi4xNjguMC4xIiwNCgkiSW5mcmFQcmVmaXgiOiAiMTcyLjE2LjAuMC8yNCIsDQoJIkdhdGV3YXkiOiAiMTkyLjE2OC4wLjIiLA0KCSJEbnNTZXJ2ZXIiOiAiOC44LjguOCIsDQoJIlBvbGljaWVzIjogW3sNCgkJCSJUeXBlIjogIkFDTCIsDQoJCQkiVmFsdWUiOiB7DQoJCQkJIlJlbW90ZUFkZHJlc3NlcyI6ICIxOTIuMTY4LjAuMTIyIiwNCgkJCQkiUmVtb3RlcG9ydHMiOiAiODA4MCIsDQoJCQkJIkFjdGlvbiI6ICJCbG9jayIsDQoJCQkJIlByb3RvY29scyI6ICI2IiwNCgkJCQkiRGlyZWN0aW9uIjogIk91dCIsDQoJCQkJIlByaW9yaXR5IjogMjAwDQoJCQl9DQoJCX0sDQoJCXsNCgkJCSJUeXBlIjogIkFDTCIsDQoJCQkiVmFsdWUiOiB7DQoJCQkJIkFjdGlvbiI6ICJBbGxvdyIsDQoJCQkJIkRpcmVjdGlvbiI6ICJPdXQiLA0KCQkJCSJQcmlvcml0eSI6IDIwMDANCgkJCX0NCgkJfQ0KCV0NCn0="
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

class ACLPolicy {
    [string] $RemoteAddresses
    [string] $Remoteports
    [string] $LocalPorts
    [string] $Action
    [string] $Protocols
    [string] $Direction
    [string] $RuleType
    [string] $Scope
    [string] $Priority

    ACLPolicy([System.Object] $policySetting) {
        if ($policySetting.psobject.Properties.name.Contains('RemoteAddresses')) { $this.RemoteAddresses = $policySetting.RemoteAddresses }
        if ($policySetting.psobject.Properties.name.Contains('RemotePorts')) { $this.RemotePorts = $policySetting.RemotePorts }
        if ($policySetting.psobject.Properties.name.Contains('LocalPorts')) { $this.LocalPorts = $policySetting.LocalPorts }
        if ($policySetting.psobject.Properties.name.Contains('Action')) { $this.Action = $policySetting.Action }
        if ($policySetting.psobject.Properties.name.Contains('Protocols')) { $this.Protocols = $policySetting.Protocols }
        if ($policySetting.psobject.Properties.name.Contains('Direction')) { $this.Direction = $policySetting.Direction }
        if ($policySetting.psobject.Properties.name.Contains('RuleType')) { $this.RuleType = $policySetting.RuleType }
        if ($policySetting.psobject.Properties.name.Contains('Scope')) { $this.Scope = $policySetting.Scope }
        if ($policySetting.psobject.Properties.name.Contains('Priority')) { $this.Priority = $policySetting.Priority }
    }

    [PSCustomObject]Populate() {
        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $settings = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'ACL')
        if ($this.RemoteAddresses -ne $null) { $settings.Add('RemoteAddresses',$this.RemoteAddresses) }
        if ($this.Action -ne $null) { $settings.Add('Action',$this.Action) }
        if ($this.Protocols -ne $null) { $settings.Add('Protocols',$this.Protocols) }
        if ($this.LocalPorts -ne $null) { $settings.Add('LocalPorts',$this.LocalPorts) }
        if ($this.Remoteports -ne $null) { $settings.Add('Remoteports',$this.Remoteports) }
        if ($this.Direction -ne $null) { $settings.Add('Direction',$this.Direction) }
        if ($this.RuleType -ne $null) { $settings.Add('RuleType',$this.RuleType) }
        if ($this.Scope -ne $null) { $settings.Add('Scope',$this.Scope) }
        if ($this.Priority -ne $null) { $settings.Add('Priority',$this.Priority) }
        $value.Add('Settings', $settings)
        return $value
    }
}

class Policy {
    [string] $Type
    [ACLPolicy] $Settings

    Policy([System.Object] $policy) {
        $this.Type = $policy.Type
        $this.Settings = [ACLPolicy]::new($policy.Value)
    }
}

class CniArgs {
    [string] $Name
    [string] $Type
    [string] $Subnet
    [string] $LocalEndpoint
    [string] $InfraPrefix
    [string] $Gateway
    [string] $DnsServer
    [Policy[]] $Policies

    CniArgs([System.Object] $cniArgs) {
        $this.Name = $cniArgs.Name
        $this.Type = $cniArgs.Type
        $this.Subnet = $cniArgs.Subnet
        $this.LocalEndpoint = $cniArgs.LocalEndpoint
        $this.InfraPrefix = $cniArgs.InfraPrefix
        $this.Gateway = $cniArgs.Gateway
        $this.DnsServer = $cniArgs.DnsServer
        for($i=0; $i -lt $cniArgs.Policies.length; $i++) {
            $policy = [Policy]::new($cniArgs.Policies[$i])
            $this.Policies += $policy
        }
    }
}

class CniConf {
    [System.Collections.Specialized.OrderedDictionary] $CniBase
    [uint16] $OptKeyParams
    [uint16] $WKOptKeyParams
    [CniArgs] $Args

    CniConf([System.Object] $cniArgs) {
        $this.CniBase = [System.Collections.Specialized.OrderedDictionary]::new()
        # Initialize arguments
        $this.Args = [CniArgs]::new($cniArgs)
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
        $this.CniBase.Add('name', $this.Args.Name)
        $this.CniBase.Add('type', $this.Args.Type)
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
                    $ipamFields.Add('subnet', $this.Args.Subnet)
                    $routes = @()
                    $routes += (@{'GW'=$this.Args.Gateway;})
                    $ipamFields.Add('routes', $routes)

                    $this.CniBase.Add('ipam', $ipamFields)
                }

                ([WKOptionalKeysFlag]::Dns).value__ {
                    $dnsFields = [System.Collections.Specialized.OrderedDictionary]::new()
                    $nameservers = @()
                    $nameservers += ($this.Args.DnsServer)
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
        $additionalArgs += $this.PopulateDefaultPolicies()

        # Populate user defined policies
        if ($this.Args.Policies.length -gt 0) {
            $additionalArgs += $this.PopulatePolicies($this.Args.Policies)
        }
        $this.CniBase.Add('AdditionalArgs', $additionalArgs)
    }

    [PSCustomObject[]] PopulateDefaultPolicies() {
        $defaultPolicies = @()

        # Default OutBoundNAT Policy
        $outboundpolicy = [System.Collections.Specialized.OrderedDictionary]::new()
        $exceptions = @()
        $exceptions += ($this.Args.Subnet)
        $exceptions += ($this.Args.LocalEndpoint)

        $value = [System.Collections.Specialized.OrderedDictionary]::new()
        $value.Add('Type', 'OutBoundNAT')
        $value.Add('Settings', @{'Exceptions' = $exceptions})
        $outboundPolicy.Add('Name', 'EndpointPolicy')
        $outboundPolicy.Add('Value', $value)
        $defaultPolicies += $outboundpolicy

        # Default ACL PolicyList
        $defaultACLpolicyList = @()
        <#1#>$defaultACLpolicyList += [Policy](@{Type='ACL';Value=@{Action='Allow';Protocols='6';LocalPorts='1111';Direction='In';Priority=101}} | ConvertTo-Json | ConvertFrom-Json)
        <#2#>$defaultACLpolicyList += [Policy](@{Type='ACL';Value=@{RemoteAddresses=$this.Args.LocalEndpoint;RemotePorts='31002';Action='Allow';Protocols='6';Direction='Out';Priority=200}} | ConvertTo-Json | ConvertFrom-Json)
        <#3#>$defaultACLpolicyList += [Policy](@{Type='ACL';Value=@{RemoteAddresses=$this.Args.InfraPrefix;Action='Block';Direction='Out';Priority=1998}} | ConvertTo-Json | ConvertFrom-Json)
        <#4#>$defaultACLpolicyList += [Policy](@{Type='ACL';Value=@{RemoteAddresses=$this.Args.Subnet;Action='Block';Direction='Out';Priority=1999}} | ConvertTo-Json | ConvertFrom-Json)
        <#5#>$defaultACLpolicyList += [Policy](@{Type='ACL';Value=@{Action='Allow';Direction='Out';Priority=2000}} | ConvertTo-Json | ConvertFrom-Json)
        $defaultPolicies += $this.PopulatePolicies($defaultACLpolicyList)

        return $defaultPolicies
    }

    [PSCustomObject[]] PopulatePolicies([System.Object[]] $policies) {
        $policyList = @()
        for ($i=0; $i -lt $policies.length; $i++) {
            $policyOut = [System.Collections.Specialized.OrderedDictionary]::new()
            $value = $policies[$i].Settings.Populate()
            $policyOut.Add('Name', 'EndpointPolicy')
            $policyOut.Add('Value', $value)
            $policyList += $policyOut
        }
        return $policyList
    }

    [String]Get() {
        $cniConfString = ConvertTo-Json -Depth 50 $this.CniBase
        return $cniConfString
    }
}

######### Main #########
[string] $DecodedText = [System.Text.Encoding]::ascii.GetString([System.Convert]::FromBase64String($CniArgs))
[System.Object] $cniArgs = $DecodedText | ConvertFrom-Json

$cniConfObj = [CniConf]::new($cniArgs)
$cniConfObj.Populate() 
$cniConfObj.Get() | Out-File -FilePath $CniConfPath -Encoding ascii
Write-Verbose -Message ("Generated CNI conf: {0}`n{1}" -f $CniConfPath, $cniConfObj.Get())
