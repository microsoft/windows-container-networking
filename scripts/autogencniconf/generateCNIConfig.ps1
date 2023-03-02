<#

This script generates CNI config from a Base64 encoded JSON string

Sample CNI Args:
{
    "Name": "azure-cni",
    "Type": "sdnbridge",
    "Subnet": "192.168.0.0/24",
    "Gateway": "192.168.0.2",
    "InfraPrefix": "10.0.0.0/24",
    "DnsServers": ["168.63.129.16"],
    "AdditionalPolicies": [{
            "Type": "ACL",
            "Settings": {
                "RemoteAddresses": "192.168.0.0/24",
                "Action": "Allow",
                "Direction": "Out",
                "Priority": 3004
            }
        },
        {
            "Type": "ACL",
            "Settings": {
                "RemoteAddresses": "10.0.0.0/24",
                "Action": "Allow",
                "Direction": "Out",
                "Priority": 3005
            }
        }
    ]
}

Validate the json using JSON Lint (https://jsonlint.com/)

Encode the JSON string with ASCII as the destination character set (https://www.base64encode.org/)

Base64 Endoded string for above:
ew0KICJOYW1lIjogImF6dXJlLWNuaSIsDQogIlR5cGUiOiAic2RuYnJpZGdlIiwNCiAiU3VibmV0IjogIjE5Mi4xNjguMC4wLzI0IiwNCiAiR2F0ZXdheSI6ICIxOTIuMTY4LjAuMiIsDQogIkluZnJhUHJlZml4IjogIjEwLjAuMC4wLzI0IiwNCiAiRG5zU2VydmVycyI6IFsiMTY4LjYzLjEyOS4xNiJdLA0KICJBZGRpdGlvbmFsUG9saWNpZXMiOiBbew0KICJUeXBlIjogIkFDTCIsDQogIlNldHRpbmdzIjogew0KICJSZW1vdGVBZGRyZXNzZXMiOiAiMTkyLjE2OC4wLjAvMjQiLA0KICJBY3Rpb24iOiAiQWxsb3ciLA0KICJEaXJlY3Rpb24iOiAiT3V0IiwNCiAiUHJpb3JpdHkiOiAzMDA0DQogfQ0KIH0sDQogew0KICJUeXBlIjogIkFDTCIsDQogIlNldHRpbmdzIjogew0KICJSZW1vdGVBZGRyZXNzZXMiOiAiMTAuMC4wLjAvMjQiLA0KICJBY3Rpb24iOiAiQWxsb3ciLA0KICJEaXJlY3Rpb24iOiAiT3V0IiwNCiAiUHJpb3JpdHkiOiAzMDA1DQogfQ0KIH0NCiBdDQp9

Report issues: containernetdev@microsoft.com

#>

[CmdletBinding()]
param (
    [parameter(Mandatory = $false)] [string] $CniConfPath = ".\cniConf",
    [parameter(Mandatory = $true)]  [string] $CniArgs,
    [parameter(Mandatory = $false)] [string] $Version = "1.0.0"
)

# Default Values/Script variables
set-variable -name DEFAULT_CNI_VERSION -value ([string]"0.2.0") -Scope Script
set-variable -name ACL_POLICY -value ([string]"ACL") -Scope Script
set-variable -name DEFAULT_PRIORITY -value ([string]"-1") -Scope Script # Used to help in sorting the policies based on priority even if priority is not specified by user
set-variable -name USER_POLICY_PRIO_START -value ([int]3000) -Scope Script
set-variable -name USER_POLICY_PRIO_END -value ([int]8000) -Scope Script

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

class Policy {
    [string] $Type
    [System.Object] $Settings

    Policy([System.Object] $policy) {
        $this.Type = $policy.Type
        $this.Settings = $policy.Settings
        if (-not $this.Settings.psobject.Properties.name.Contains('Priority')) {$this.Settings | Add-Member -MemberType NoteProperty -Name "Priority" -Value $script:DEFAULT_PRIORITY}
    }
}

class CniArgs {
    [string] $Name
    [string] $Type
    [string] $Version
    [string] $Subnet
    [string] $Gateway
    [string] $InfraPrefix
    [string] $ManagementIp
    [string[]] $DnsServers
    [Policy[]] $AdditionalPolicies
    [bool] $SkipDefaultPolicies # Undocumented parameter to disable system policies

    CniArgs([System.Object] $cniArgs) {
        # Mandatory Parameters
        $this.Name = $cniArgs.Name
        $this.Type = $cniArgs.Type
        $this.Subnet = $cniArgs.Subnet
        $this.Gateway = $cniArgs.Gateway
        $this.ManagementIp = $cniArgs.ManagementIp
        $this.InfraPrefix = $cniArgs.InfraPrefix
        $this.DnsServers = $cniArgs.DnsServers

        # Optional Parameters
        if ($cniArgs.psobject.Properties.name.Contains('Version')) {$this.Version = $cniArgs.Version} else {$this.Version = $script:DEFAULT_CNI_VERSION}
        if ($cniArgs.psobject.Properties.name.Contains('SkipDefaultPolicies')) {$this.SkipDefaultPolicies = $true} else {$this.SkipDefaultPolicies = $false}
        if ($cniArgs.psobject.Properties.name.Contains('AdditionalPolicies')) {
            for($i=0; $i -lt $cniArgs.AdditionalPolicies.length; $i++) {
                # Following constraints are ensured for policy priorities (HNS supports priorities between 100-65500 for ACLs)
                # 1. System defined policies have 2 bands:
                #    a. Non-negotiable: 2000-3000, cannot be overridden by user-defined policies
                #    b. Negotiable: > 8000, van be overridden by user-defined policies
                # 2. User defined policies should have priorities between 3001 - 8000
                # 3. Policies should be populated in ascending order of priorities to help in debugging (handled in populate APIs)
                #    |--------------------------------------------|
                #    |                Priority Bands              |
                #    |----------------|--------------|------------|
                #    |    2000-2999   |   3000-8000  |   >8000    |
                #    |----------------|--------------|------------|
                #    | Non-negotiable | User-defined | Negotiable |  
                #    |----------------|--------------|------------|
                #

                if($cniArgs.AdditionalPolicies[$i].Type -eq $script:ACL_POLICY) {
                    $userPolicySetting = $cniArgs.AdditionalPolicies[$i].Settings
                    # Ensure user-defined policy priorities are between 100-4096
                    if(-not (($userPolicySetting.Priority -ge $script:USER_POLICY_PRIO_START) -and ($userPolicySetting.Priority -le $script:USER_POLICY_PRIO_END))) {
                        Write-Verbose -Message ("User-defined ACL policies should have priority between {0} - {1}. Invalid policy: {2}" -f $script:USER_POLICY_PRIO_START, $script:USER_POLICY_PRIO_END, $userPolicySetting)
                        throw "User-defined ACL policies should have priority between 100 - 4096. Invalid policy: $userPolicySetting"
                    }
                }

                $policy = [Policy]::new($cniArgs.AdditionalPolicies[$i])
                $this.AdditionalPolicies += $policy
            }
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
        $this.CniBase.Add('cniVersion', $this.Args.Version)
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
                    $this.CniBase.Add('master', 'Ethernet')
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
                    $nameservers += ($this.Args.DnsServers)
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

        if (-not $this.Args.SkipDefaultPolicies) {
            $this.Args.AdditionalPolicies += $this.GetDefaultPolicies()
        }

        # Populate user defined policies
        Write-Verbose -Message ("Number of policies: {0}" -f $this.Args.AdditionalPolicies.length)
        if ($this.Args.AdditionalPolicies.length -gt 0) {
            $this.Args.AdditionalPolicies = $this.Args.AdditionalPolicies |  Sort-Object -Property @{e={$_.Settings.Priority}}
            $this.CniBase.Add('AdditionalArgs', $this.PopulatePolicies())
        }
    }

    [PSCustomObject[]] GetDefaultPolicies() {
        $defaultPolicies = @()
        # Default PolicyList
        <#1#>$defaultPolicies += [Policy](@{Type='OutBoundNAT';Settings=@{Exceptions=@($this.Args.Subnet, ('{0}/32' -f $this.Args.ManagementIp))}} | ConvertTo-Json | ConvertFrom-Json)
        <#2#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{RemoteAddresses=$this.Args.InfraPrefix;Action='Block';Direction='Out';Priority=9001}} | ConvertTo-Json | ConvertFrom-Json)
        <#3#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{RemoteAddresses=$this.Args.Subnet;Action='Block';Direction='Out';Priority=9002}} | ConvertTo-Json | ConvertFrom-Json)
        <#4#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{Action='Allow';Direction='Out';Priority=9003}} | ConvertTo-Json | ConvertFrom-Json)
        # WireServer ACL policies
        <#5#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{RemoteAddresses='168.63.129.16/32';RemotePorts='53';Action='Allow';Protocols='6';Direction='Out';Priority=2051}} | ConvertTo-Json | ConvertFrom-Json)
        <#6#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{RemoteAddresses='168.63.129.16/32';RemotePorts='53';Action='Allow';Protocols='17';Direction='Out';Priority=2052}} | ConvertTo-Json | ConvertFrom-Json)
        <#7#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{RemoteAddresses='168.63.129.16/32';Action='Block';Direction='Out';Priority=2053}} | ConvertTo-Json | ConvertFrom-Json)
        <#8#>$defaultPolicies += [Policy](@{Type='ACL';Settings=@{RemoteAddresses='169.254.169.254/32';Action='Block';Direction='Out';Priority=2054}} | ConvertTo-Json | ConvertFrom-Json)

        for($i=0; $i -lt $defaultPolicies.length; $i++) {
            # Ensure system policy priorities are either 2000-3000 (non-negotiable band) or >8000 (negotiable band)
            $policySetting = $defaultPolicies[$i].Settings
            if($defaultPolicies[$i].Type -eq $script:ACL_POLICY) {
                # Assumption: System ACL policies are always configured with priorities.
                if( -not ((($policySetting.Priority -gt '0') -and ($policySetting.Priority -lt $script:USER_POLICY_PRIO_START)) -or ($policySetting.Priority -gt $script:USER_POLICY_PRIO_END))) {
                    Write-Verbose -Message ("System ACL policies should have priority either between 2000 - 2999 or above {0}. Invalid policy: {1}" -f $script:USER_POLICY_PRIO_END, $policySetting)
                    throw "System ACL policies should have priority either between 2000-2999 or above 8000. Invalid policy: $policySetting"
                }
            } else{
                # Use DEFAULT_PRIORITY for policies whose priorities need not be specified
                if (-not $policySetting.psobject.Properties.name.Contains('Priority')) {
                    $policySetting | Add-Member -MemberType NoteProperty -Name "Priority" -Value $script:DEFAULT_PRIORITY
                }
            }
        }

        return $defaultPolicies
    }

    [PSCustomObject[]] PopulatePolicies() {
        $policyList = @()
        $policies = $this.Args.AdditionalPolicies
        for ($i=0; $i -lt $policies.length; $i++) {
            $policyOut = [System.Collections.Specialized.OrderedDictionary]::new()
            $policyOut.Add('Name', 'EndpointPolicy')
            # No need to populate default priority for policies
            if (($policies[$i].Settings.psobject.Properties.name.Contains('Priority')) -and ($policies[$i].Settings.Priority -eq $script:DEFAULT_PRIORITY)) {
                $policies[$i].Settings = $policies[$i].Settings | Select-Object -Property * -ExcludeProperty 'Priority'
            }
            $policyOut.Add('Value', $policies[$i])
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
Write-Verbose -Message ("Cni Args: {0}`n" -f $DecodedText)
[System.Object] $cniArgs = $DecodedText | ConvertFrom-Json
$cniConfObj = [CniConf]::new($cniArgs)
$cniConfObj.Populate() 
$cniConfObj.Get() | Out-File -FilePath $CniConfPath -Encoding ascii
Write-Verbose -Message ("Generated CNI conf: {0}`n{1}" -f $CniConfPath, $cniConfObj.Get())

# Cleanup Script variables
Remove-Variable -Name DEFAULT_CNI_VERSION -Scope Script
Remove-Variable -name DEFAULT_PRIORITY -Scope Script
Remove-Variable -name ACL_POLICY -Scope Script
Remove-Variable -name USER_POLICY_PRIO_START -Scope Script
Remove-Variable -name USER_POLICY_PRIO_END -Scope Script
