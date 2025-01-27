#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
  This script deploys the network on container host based on user requirements and generates a CNI config file to be used by containers to create endpoint.
#>

[CmdletBinding()]
param (
    [ValidateSet('Validate', 'Install', 'CleanInstall')]
    [string]
    $Action,

    [string]
    $CniConfPath,

    [string]
    $CniConfTemplatePath,

    [ValidateSet('L2Bridge', 'L2Tunnel', 'NAT')]
    [string]
    $NetworkType,

    [parameter(Mandatory = $false)]
    [bool]
    $WithoutAcls = $false,

    [string]
    $CniArgs,

    [parameter(Mandatory = $false)]
    [int]
    $DhcpTimeout = -1
)

# Default values/Script variables
$Global:BaseNetworkName = 'External'
$Global:enableDualStack = $false
Set-Variable -Name DHCP_CHECK_TIMEOUT_MIN -Value ([int]60) -Scope Script
Set-Variable -Name DHCP_CHECK_TIMEOUT_MAX -Value ([int]600) -Scope Script
Set-Variable -Name DHCP_CHECK_TIMEOUT_UNINITIALIZED -Value ([int]-1) -Scope Script
Set-Variable -Name APIPA_RANGE_START -Value ([string]'169.254.0.1') -Scope Script
Set-Variable -Name APIPA_RANGE_END -Value ([string]'169.254.255.254') -Scope Script

# skip warnings about HNS commands using unapproved verbs
Import-Module -Force -Verbose:$False -DisableNameChecking $PSScriptRoot\HNS.V2.psm1

# Utility Functions
# -------------------------------
function Test-IpAddressInRange {
    # This function is only for v4 address ranges, dual stack networks also have an IpV4 management address
    param (
        [string] $startIp,
        [string] $endIp,
        [string] $targetIp
    )
    return (([version]$startIp -le [version]$targetIp) -and ([version]$endIp -ge [version]$targetIp))
}
# -------------------------------


function getOSBuildNumber() {
    return (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
}

function Get-PrimaryInterface {
    $ManagementIp = ''
    $infraPrefix = $null
    try {
        # If the script is being run on an Azure machine, the server on the ip here
        # will return information about the machine's interfaces. We use this information
        # to determine the management ip for the network, and the Infrastructure Prefix.
        # This allows us to setup networking correctly. We also determine whether to use
        # Azure or corp dns here
        $res = Invoke-WebRequest -UseBasicParsing 'http://168.63.129.16:80/machine/plugins?comp=nmagent&type=getinterfaceinfov1' `
            -ErrorAction SilentlyContinue -ErrorVariable err
        Write-Verbose 'Was able to contact metadata server.'
    } catch {
        Write-Verbose "Problem contacting metadata server: $err"
    }
    if ( -not [string]::IsNullOrEmpty($err) ) {
        Write-Verbose 'Assuming Non-Azure Deployment'
        # This attempts to get a Management Ip for an interface on the host

        # Test-Connection changed arguments and return value type in Powershell 6.
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $result = Test-Connection -ComputerName $env:COMPUTERNAME -Count 1 -IPv4
            $ManagementIp = $result.Address.IPAddressToString
        } else {
            $result = Test-Connection -ComputerName $env:COMPUTERNAME -Count 1
            $ManagementIp = $result.IPV4Address.IPAddressToString
        }

        $dnsServer = '10.50.10.50'
    } else {
        Write-Verbose 'Assuming Azure Deployment'
        $c = $res.Content
        Write-Verbose "XML content:`n$c"

        #  Example XML doc:
        #
        # <Interfaces>
        #     <Interface MacAddress="" IsPrimary="true">
        #         <IPSubnet Prefix="">
        #             <IPAddress Address="127.0.0.1" IsPrimary="true" />
        #             <IPAddress Address="127.0.0.2" IsPrimary="false" />
        #             <IPAddress Address="127.0.0.3" IsPrimary="false" />
        #         </IPSubnet>
        #     </Interface>
        #     <Interface MacAddress="" IsPrimary="false">
        #         <IPSubnet Prefix="">
        #             <IPAddress Address="127.0.0.1" IsPrimary="true" />
        #             <IPAddress Address="127.0.0.2" IsPrimary="false" />
        #             <IPAddress Address="127.0.0.3" IsPrimary="false" />
        #         </IPSubnet>
        #     </Interface>
        # </Interfaces>
        $iface = ([xml]$c).Interfaces.Interface

        $iface | Where-Object IsPrimary -EQ 'true' | ForEach-Object {
            Write-Verbose "Primary interface: $($_.MacAddress)"
            $subnetObj = $_.IPSubnet

            $subnetObj.IPAddress | Where-Object IsPrimary -EQ 'true' | ForEach-Object {
                Write-Verbose "Primary IPAddress: $($_.Address)"

                $ManagementIp = [string]$_.Address
                $infraPrefix = [string]$subnetObj.Prefix
            }
        }
        $dnsServer = '168.63.129.16'

        if ( [string]::IsNullOrEmpty($ManagementIp) ) {
            throw "Get-PrimaryInterface failed to get network config: $c."
        }
    }

    return $ManagementIp, $infraPrefix, $dnsserver
}

function Get-InfraDataV6 {
    param (
        [parameter(Mandatory = $true)] [string]
        $ManagementIp
    )
    $ManagementIpv6 = ''
    $infraPrefixv6 = $null

    try {
        $resv6 = Invoke-RestMethod -Headers @{'Metadata' = 'true' } -Method GET -Uri 'http://169.254.169.254/metadata/instance/network?api-version=2021-02-01' -ErrorVariable err
    }
    catch {
        Write-Verbose "Problem contacting metadata server: $err"
    }
    if ( -not [string]::IsNullOrEmpty($err) ) {
        Write-Verbose 'Assuming Non-Azure Deployment'
        # Grab the non link local address from the same interface as the IPv4 address
        $ipv4Address = Get-NetIPAddress | Where-Object IPAddress -EQ $ManagementIp
        $ipv6addrs = Get-NetIPAddress | Where-Object InterfaceIndex -EQ $ipv4Address.InterfaceIndex |
            Where-Object AddressFamily -EQ 'IPv6' | Where-Object IPAddress -NotMatch 'fe80::'
        $ManagementIpv6 = $ipv6addrs
    }
    else {
        Write-Verbose 'Assuming Azure Deployment'
        # Grab the IPv6 info from the Primary interface
        $resv6 | ForEach-Object -Process {
            if ($_.interface.ipv4.ipAddress.privateIpAddress -eq $ManagementIp) {
                $ManagementIpv6 = $_.interface.ipv6.ipaddress.privateIpAddress
                #calculating the v6 prefix based on the v4 value
                $v6Prefix = 128 - (32 - $_.interface.ipv4.subnet.prefix)
                $infraPrefixv6 = ($ManagementIpv6 -replace '::.*') + "::/$($v6Prefix)"
            }
        }
        if ( -not $ManagementIpv6 ) {
            throw "Get-PrimaryInterface failed to get IPV6 network config: $c."
        }
        if ( -not $infraPrefixv6 ) {
            throw 'Failed to get IPv6 infraPrefix. Please add to CNI args if this is an Azure environment'
        }
    }

    return $ManagementIpv6, $infraPrefixv6
}

function Create-HostEndpoint {
    param
    (
        [parameter(Mandatory = $true)] [string] $networkId,
        [parameter(Mandatory = $true)] [System.Collections.ArrayList] $localEndpoint,
        [parameter(Mandatory = $true)] [System.Collections.ArrayList] $AddressPrefix,
        [parameter(Mandatory = $true)] [string] $IfIndex
    )

    if ($Global:enableDualStack) {
        Write-Verbose "Going to attach host endpoint IP: $($localEndpoint[0]), $($localEndpoint[1])"
        $hnsEndpoint = New-HnsEndpoint -NetworkId $networkId -Name 'bridge_gw' -IPAddress $localEndpoint[0] `
            -GatewayAddress '0.0.0.0' -Verbose -IPv6Address $localEndpoint[1] -GatewayAddressV6 '::' `
            -ErrorVariable err -ErrorAction SilentlyContinue
    }
    else {
        Write-Verbose "Going to attach host endpoint IP: $($localEndpoint[0])"
        $hnsEndpoint = New-HnsEndpoint -NetworkId $networkId -Name 'bridge_gw' -IPAddress $localEndpoint[0] `
            -GatewayAddress '0.0.0.0' -Verbose -ErrorVariable err -ErrorAction SilentlyContinue
    }

    Attach-HnsHostEndpoint -EndpointID $hnsEndpoint.Id -CompartmentID 1 -ErrorVariable err -ErrorAction SilentlyContinue

    Write-Verbose "Going to add route for host endpoint IP: $($localEndpoint[0]) to target subnet: $($AddressPrefix[0]) on interface $($IfIndex)"
    $r = New-NetRoute -DestinationPrefix $AddressPrefix[0] -InterfaceIndex $IfIndex `
        -NextHop 0.0.0.0 -RouteMetric 400 -ErrorVariable err -ErrorAction SilentlyContinue
    $r | Format-Table

    if ($Global:enableDualStack) {
        Write-Verbose "Going to add route for host endpoint IP: $($localEndpoint[1]) to target subnet: $($AddressPrefix[1]) on interface $($IfIndex)"
        $rv6 = New-NetRoute -DestinationPrefix $AddressPrefix[1] -InterfaceIndex $IfIndex `
            -NextHop '::' -RouteMetric 400 -ErrorVariable err -ErrorAction SilentlyContinue
        $rv6 | Format-Table
    }
}

function IsInterfacePhysical {
    param
    (
        [Parameter(Mandatory = $true)] [string] $IfIndex
    )
    $isPhys = Get-NetAdapter -Physical | Where-Object { $_.ifIndex -eq $IfIndex }
    return $null -ne $isPhys
}

function Find-IpInterfaceAndRoutes {
    param
    (
        [parameter(Mandatory = $True)] [string] $managementIp
    )

    $ipinterface = $null
    $ipinterface = Get-WmiObject -Namespace root\StandardCimv2 -Class MSFT_NetIPAddress |
        Where-Object { $_.IPAddress.StartsWith("$managementIp") -and $_.AddressFamily -eq 2 }

    if ($null -eq $ipinterface) {
        Throw 'No Interface found that matches requirements'
    }

    Write-Verbose "Found ip on interface: $($ipinterface.InterfaceIndex)"

    $routes = Get-NetRoute -ifIndex $ipinterface.InterfaceIndex

    return $ipinterface, $routes
}

function Wait-ForInterface {
    param
    (
        [parameter(Mandatory = $true)] [string] $managementIp,
        [parameter(Mandatory = $true)] $ifIndex
    )

    #wait for the IP to come back
    for ($i = 1; $i -le 60; $i++) {
        Write-Verbose -Message "waiting for IP: $managementIp to come back..."
        $ipaddr = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $managementIp -ErrorVariable $err -ErrorAction SilentlyContinue
        if ($null -ne $err) {
            Write-Verbose -Message $err[0].Exception
            Start-Sleep 2
        } else {
            $ipinterface, $routes = Find-IpInterfaceAndRoutes -managementIp $managementIp
            if ($ifIndex -ne $ipinterface.InterfaceIndex) {
                break
            }
        }
    }
    if ($null -ne $err) {
        Throw "IP address didn't come back"
    }
}

function FixRoutesForInterface {
    param
    (
        [parameter(Mandatory = $true)] $ipInterface,
        [parameter(Mandatory = $true)] $originalRoutes,
        [parameter(Mandatory = $true)] $newRoutes

    )

    # Recreate the routes that are not present anymore
    $a = @()
    $originalRoutes | ForEach-Object {
        $a += [PSCustomObject]@{
            ifIndex           = $_.ifIndex
            DestinationPrefix = $_.DestinationPrefix
            NextHop           = $_.NextHop
            RouteMetric       = $_.RouteMetric
        }
    }
    $b = @()
    $newRoutes | ForEach-Object {
        $b += [PSCustomObject]@{
            ifIndex           = $_.ifIndex
            DestinationPrefix = $_.DestinationPrefix
            NextHop           = $_.NextHop
            RouteMetric       = $_.RouteMetric
        }
    }

    $missing = Compare-Object -Property 'DestinationPrefix' -ReferenceObject $a -DifferenceObject $b -PassThru
    $missingStr = $missing | Format-Table | Out-String
    Write-Verbose "Missing routes for interface: $($ipInterface.InterfaceIndex) $missingStr"

    $missing | Where-Object SideIndicator -EQ '<=' | ForEach-Object -Process {
        Write-Verbose "Adding missing route: $($_.ifIndex): $($_.DestinationPrefix)"

        $r = New-NetRoute -DestinationPrefix $_.DestinationPrefix `
            -NextHop $_.NextHop -ifIndex $ipInterface.InterfaceIndex -RouteMetric $_.RouteMetric `
            -ErrorVariable err -ErrorAction SilentlyContinue

        if ($null -ne $err) {
            Write-Verbose "Ex: $err"
        } else {
            $r | Format-Table
        }
    }
}

function Remove-EndpointRoute {
    param(
        [parameter(Mandatory = $true)] [string]
        $IfIndex,

        [parameter(Mandatory = $true)] [string]
        $LocalEndpointIp,

        [parameter(Mandatory = $true)] [string]
        $AddressPrefix,

        [parameter(Mandatory = $true)] [string]
        $NextHop
    )
    $eps = Get-HnsEndpoint

    $hnsEndpoint = $eps | Where-Object { $_.IPAddress -eq $localEndpointIp }
    if ($null -ne $hnsEndpoint) {
        Write-Verbose "Going to detach host endpoint: $hnsEndpoint"
        Remove-NetRoute -DestinationPrefix $AddressPrefix -InterfaceIndex $IfIndex -NextHop $NextHop `
            -Confirm:$false -ErrorVariable err -ErrorAction SilentlyContinue
        if ($null -ne $err) {
            Write-Verbose "Problem removing route: $err[0].Exception"
        }

        Detach-HnsHostEndpoint -EndpointID $hnsEndpoint.Id
    }
}

function Remove-AllEndpointsForNetworkType {
    param(
        [string]
        $NetworkType
    )
    $nets = ((Get-HnsNetwork) | Where-Object { $_.Type -eq $NetworkType })

    foreach ($net in $nets) {
        $eps = (Get-HnsEndpoint | Where-Object { $_.VirtualNetwork -eq $net.ID })
        Write-Verbose "Current active endpoints for type [$NetworkType]: $eps"
        foreach ($ep in $eps) {
            Remove-HnsEndpoint $ep
        }
    }
}

function Remove-AllNetworks {
    param
    (
        [string]
        $ExcludedNetworkName,

        [String]
        $NetworkType
    )
    $nets = Get-HnsNetwork | Where-Object { $_.Type.ToLower() -eq $NetworkType.ToLower() -and $_.Name -ne $ExcludedNetworkName }
    Write-Verbose "Current active networks for type [$NetworkType]: $nets"
    Write-Verbose "Removing active networks for type [$NetworkType]"
    $nets | Remove-HnsNetwork
}

function Cleanup-BridgeNetwork {
    param
    (
        [ValidateSet('L2Bridge', 'L2Tunnel')]
        [parameter(Mandatory = $true)]  [string] $networkType,
        [parameter(Mandatory = $true)]  [string] $BaseNetworkName,
        [parameter(Mandatory = $false)] [System.Collections.ArrayList] $AddressPrefix,
        [parameter(Mandatory = $false)] [System.Collections.ArrayList] $localEndpoint,
        [parameter(Mandatory = $false)] [string] $IfIndex
    )
    # Since endpoints are deleted by removing the network, we delete them explicitly here and remove the endpoint route(s) as well
    Cleanup-EndpointsForBridgeNetwork -networkType $networkType -AddressPrefix $AddressPrefix[0] `
        -localEndpoint $localEndpoint[0] -IfIndex $IfIndex -NextHop '0.0.0.0'
    if ($Global:enableDualStack) {
        Cleanup-EndpointsForBridgeNetwork -networkType $networkType -AddressPrefix $AddressPrefix[1] `
            -localEndpoint $localEndpoint[1] -IfIndex $IfIndex -NextHop '::'
    }
    Remove-AllNetworks -ExcludedNetworkName $BaseNetworkName -NetworkType $networkType
}

function  Cleanup-EndpointsForBridgeNetwork {
    param (
        [parameter(Mandatory = $true)]  [string] $networkType,
        [parameter(Mandatory = $false)] [string] $AddressPrefix,
        [parameter(Mandatory = $false)] [string] $localEndpoint,
        [parameter(Mandatory = $false)] [string] $IfIndex,
        [parameter(Mandatory = $false)] [string] $NextHop
    )
    # If network was creatred with localEndpoint, we need to remove the route
    if ( -not [string]::IsNullOrEmpty($localEndpoint) ) {
        Remove-EndpointRoute -ifIndex $IfIndex -localEndpointIp $localEndpoint -AddressPrefix $AddressPrefix -NextHop $NextHop
    }
    Remove-AllEndpointsForNetworkType -NetworkType $networkType
}

function Ensure-BaseNetwork {
    param
    (
        [ValidateSet('L2Bridge', 'L2Tunnel')]
        [parameter(Mandatory = $true)]  [string] $networkType,
        [parameter(Mandatory = $true)]  [string] $BaseNetworkName,
        [parameter(Mandatory = $true)]  [string] $ManagementIp
    )

    if ( -not (Get-HnsNetwork | Where-Object Name -EQ $BaseNetworkName) ) {
        # Create a L2Bridge network to trigger a vSwitch creation. Do this only once as it causes network blip
        $IpInterface, $routes = Find-IpInterfaceAndRoutes -managementIp $ManagementIp
        Write-Verbose $ipinterface.InterfaceAlias
        if ( -not (IsInterfacePhysical -ifIndex $IpInterface.InterfaceIndex) ) {
            Throw 'No Physical Adapters Available'
        }
        if ($Global:enableDualStack) {
            New-HNSNetwork -Type $NetworkType -AddressPrefix @('192.168.255.0/30', '90::00/120') -Gateway @('192.168.255.1', '90::01') `
                -Name $BaseNetworkName -AdapterName $ipinterface.InterfaceAlias -Verbose
        }
        else {
            New-HNSNetwork -Type $NetworkType -AddressPrefix @('192.168.255.0/30') -Gateway @('192.168.255.1') `
                -Name $BaseNetworkName -AdapterName $ipinterface.InterfaceAlias -Verbose
        }
        Wait-ForInterface -managementIp $managementIp -ifIndex $IpInterface.InterfaceIndex
    }

}

function Create-PrimaryNetwork {
    param
    (
        [ValidateSet('L2Bridge', 'L2Tunnel')]
        [parameter(Mandatory = $true)]  [string] $networkType,
        [parameter(Mandatory = $true)]  [string] $networkName,
        [parameter(Mandatory = $true)]  [System.Collections.ArrayList] $AddressPrefix,
        [parameter(Mandatory = $true)]  [System.Collections.ArrayList] $Gateway,
        [parameter(Mandatory = $false)] [System.Collections.ArrayList] $localEndpoint,
        [parameter(Mandatory = $false)] [string] $ManagementIp
    )

    $IpInterface, $originalRoutes = Find-IpInterfaceAndRoutes -managementIp $managementIp
    $hnsnet = New-HnsNetwork -Verbose -Type $networkType -Name $networkName -AddressPrefix $AddressPrefix -Gateway $Gateway
    Write-Verbose "result $hnsnet"
    #wait for the IP to come back
    Wait-ForInterface -managementIp $managementIp -ifIndex $IpInterface.InterfaceIndex
    $IpInterface, $routes = Find-IpInterfaceAndRoutes -managementIp $managementIp
    FixRoutesForInterface -ipInterface $IpInterface -originalRoutes $originalRoutes -newRoutes $routes
    $IpInterface, $routes = Find-IpInterfaceAndRoutes -managementIp $managementIp
    Create-HostEndpoint -networkId $hnsnet.ID -localEndpoint $localEndpoint `
        -AddressPrefix $AddressPrefix -IfIndex $IpInterface.InterfaceIndex
    return $hnsnet

}

function Setup-BridgeNetwork {
    param
    (
        [ValidateSet('L2Bridge', 'L2Tunnel')]
        [parameter(Mandatory = $true)]  [string] $networkType,
        [parameter(Mandatory = $true)]  [string] $networkName,
        [parameter(Mandatory = $true)]  [System.Collections.ArrayList] $AddressPrefix,
        [parameter(Mandatory = $true)]  [System.Collections.ArrayList] $Gateway,
        [parameter(Mandatory = $false)] [System.Collections.ArrayList] $localEndpoint,
        [parameter(Mandatory = $True)]  [string] $ManagementIp,
        [parameter(Mandatory = $true)]  [string] $cleanup
    )

    $IpInterface, $originalRoutes = Find-IpInterfaceAndRoutes -managementIp $managementIp
    $originalRoutesStr = $originalRoutes | Format-Table | Out-String
    Write-Verbose "Routes for interface: $($ipInterface.InterfaceIndex) $originalRoutesStr"

    Ensure-BaseNetwork -networkType $networkType -BaseNetwork $Global:BaseNetworkName `
        -ManagementIp $ManagementIp
    $baseNet = Get-HnsNetwork | Where-Object Name -EQ $Global:BaseNetworkName
    $ManagementIp = $baseNet.ManagementIp
    $IpInterface, $routes = Find-IpInterfaceAndRoutes -managementIp $managementIp
    if (IsInterfacePhysical -IfIndex $IpInterface.InterfaceIndex) {
        Write-Verbose 'IP is attached to physcial interface, no cleanup needed'
    } else {
        Write-Verbose 'IP is attached to virtual interface, cleaning up networks on it'

        Cleanup-BridgeNetwork -networkType $NetworkType -BaseNetworkName $Global:BaseNetworkName `
            -AddressPrefix $AddressPrefix -localEndpoint $localEndpoint `
            -IfIndex $IpInterface.InterfaceIndex
    }


    if ($cleanup -eq $true) {
        Write-Verbose 'Cleanup only, done'
        return 0
    }

    $hnsnet = Create-PrimaryNetwork -networkType $NetworkType -networkName $NetworkName `
        -AddressPrefix $AddressPrefix -Gateway $Gateway -localEndpoint $localEndpoint `
        -ManagementIp $ManagementIp

    Write-Verbose 'All done'

    $IpInterface, $routes = Find-IpInterfaceAndRoutes -managementIp $managementIp
    $routesStr = $routes | Format-Table | Out-String
    Write-Verbose "Routes for interface: $($ipInterface.InterfaceIndex) $routesStr"

    FixRoutesForInterface -ipInterface $IpInterface -originalRoutes $originalRoutes -newRoutes $routes

    return $hnsnet
}

function Validate-HNSRequirements {
    $hnsVersion = Invoke-HnsRequest -Type 'globals' -Method 'GET' -Id 'version'
    # return can either be a string or an object
    if ( ($null -eq $hnsVersion) -or [string]::IsNullOrWhiteSpace($hnsVersion) ) {
        throw 'Unable to retrieve HNS version'
    }

    Write-Verbose -Message ('Detected HNS Version {0}.{1}' -f @($hnsVersion.Major, $hnsVersion.Minor))
    # ConvertFrom-Json (used in Get-HnsGlobalVersion) deserializes integers as Int64 starting in PowerShell 6.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $minVersion = [tuple]::Create([Int64]9, [Int64]2)
    } else {
        $minVersion = [tuple]::Create([Int32]9, [Int32]2)
    }
    $version = [tuple]::Create($hnsVersion.Major, $hnsVersion.Minor)
    if ($version -lt $minVersion) {
        throw 'HNS version is not supported'
    }
}

function Enable-HNSFeatures {
    $osBuildNum = getOSBuildNumber
    if ([int]$osBuildNum -ne 17763) {
        return
    }

    $regEntries = @(
        [pscustomobject]@{
            Path  = 'HKLM:\SYSTEM\CurrentControlSet\Services\hns\State'
            Name  = 'EnableCompartmentNamespace'
            Type  = 'DWORD'
            Value = '1'
        }
    )

    foreach ( $reg in $regEntries.GetEnumerator() ) {
        $value = Get-ItemProperty -Path $reg.Path -Name $reg.Name -ErrorAction Ignore
        if ($null -eq $value) {
            New-ItemProperty -Path $reg.Path -Name $reg.Name -PropertyType $reg.Type -Value $reg.Value | Out-Null
            Write-Verbose -Message ('Enabled HNS Feature {0}' -f $reg.Name)
        }
    }
}

function Test-IsApipa {
    param (
        [parameter(Mandatory = $true)] [string]
        [string] $ipToCheck
    )

    if ((Test-IpAddressInRange -startIp $Script:APIPA_RANGE_START -endIp $Script:APIPA_RANGE_END -targetIp $ipToCheck)) {
        return $true
    } else {
        return $false
    }
}

function Wait-ForIpOnAnyInterface {
    param (
        [parameter(Mandatory = $true)] [string]
        $ipToCheck,
        [parameter(Mandatory = $true)] [int]
        $timeToWait
    )

    Write-Verbose -Message ('Waiting for {0} secs, IP {1} to be assigned on an interface' -f $timeToWait, $ipToCheck)
    $timeWaited = 0
    $sleepInterval = 10
    while ($timeWaited -le $timeToWait) {
        $ipAddressObj = Get-NetIPAddress | Where-Object IPAddress -eq $ipToCheck
        if ($null -ne $ipAddressObj) {
            # An interface now exists with this IP.
            Write-Verbose -Message ('IP {0} found after waiting for {1} seconds' -f $ipToCheck, $timeWaited)
            return $true
        }
        Start-Sleep -Seconds $sleepInterval
        $timeWaited += $sleepInterval
    }
    Write-Verbose -Message ('IP {0} not found after waiting for {1} seconds' -f $ipToCheck, $timeToWait)
    return $false
}

function Wait-ForValidHnsMgmtIp {
    param (
        [ValidateSet('L2Bridge', 'L2Tunnel', 'nat')]
        [parameter(Mandatory = $true)] [string]
        $NetworkType,

        [parameter(Mandatory = $true)] [string]
        $NetworkName,

        [parameter(Mandatory = $true)] [string]
        $requiredMgmtIp,

        [parameter(Mandatory = $true)] [int]
        $dhcpCheckTimeout
    )

    if ($dhcpCheckTimeout -eq $Script:DHCP_CHECK_TIMEOUT_UNINITIALIZED) {
        Write-Verbose -Message ('Skipping HnsMgmtIp validation as dhcpCheckTimeout is not set')
        return
    }

    if ($NetworkType -eq "nat") {
        Write-Verbose -Message ('Skipping HnsMgmtIp validation as networktype is nat')
        return
    }

    $network = Get-HnsNetwork | ? Name -eq $NetworkName
    if (-not $network) {
        Write-Verbose -Message ('Skipping HnsMgmtIp validation as HNS network not found')
        return
    }

    Write-Verbose -Message ('Validating existing HNS network')
    if ($network.ManagementIP -eq $requiredMgmtIp) {
        Write-Verbose -Message ('IP on network {0} already matches required management IP {1}' -f $network.managementIP, $requiredMgmtIp)
        return
    }

    if (-not (Test-IsApipa -ipToCheck $network.managementIP)) {
        Write-Warning -Message ('Found a non-apipa IP {0} on existing HNS network, which does not match with management IP {1} which was expected on the network.' -f $network.managementIP, $requiredMgmtIp)
        return
    }

    # Before the management adapter gets a DHCP IP, it contains an APIPA IP.
    # If the network gets rehydrated in HNS even before DHCP IP was assigned
    # to the management interface, we could reach this code block.
    Write-Warning -Message ('Found an apipa HNS mgmt IP {0}' -f $network.managementIP)

    # Now, we wait for an interface to get the $requiredMgmtIp via DHCP.
    $ipArrived = Wait-ForIpOnAnyInterface -ipToCheck $requiredMgmtIp -timeToWait $dhcpCheckTimeout
    if ($ipArrived -eq $false) {
        Write-Warning -Message ('Couldnt find management IP {0}. HNS Network validation Failed.' -f $requiredMgmtIp)
    }

    # Now, we can try restarting HNS. It should get the new management IP after restart.
    Restart-Service -f Hns
    Start-Sleep -Seconds 3
    $netPostRestart = Get-HnsNetwork | ? Name -eq $network.name
    if (-not $netPostRestart) {
        Write-Warning -Message ('Couldnt find HNS network after restart')
        return
    }

    if ($netPostRestart.ManagementIP -ne $requiredMgmtIp) {
        Write-Warning -Message ('Despite restarting HNS, network named {0} has management IP {1} which differs from the one expected {2}. HNS Network validation Failed.' -f $NetworkName, $netPostRestart.ManagementIP, $requiredMgmtIp)
        return
	}

    Write-Verbose -Message ('Restarting HNS network after DHCP assignment was successful.')
}

function Wait-ForValidMgmtIp {
    param (
        [ValidateSet('L2Bridge', 'L2Tunnel', 'nat')]
        [parameter(Mandatory = $true)] [string]
        $NetworkType,

        [parameter(Mandatory = $true)] [string]
        $CurrentManagementIp,

        [parameter(Mandatory = $true)] [int]
        $dhcpCheckTimeout
    )

    if ($dhcpCheckTimeout -eq $Script:DHCP_CHECK_TIMEOUT_UNINITIALIZED) {
        Write-Verbose -Message ('Skipping MgmtIp validation as dhcpCheckTimeout is not set')
        return $CurrentManagementIp
    }

    if ($NetworkType -eq "nat") {
        Write-Verbose -Message ('Skipping MgmtIp validation as networktype is nat')
        return $CurrentManagementIp
    }

    $validIpFound = $false
    $timeout = $dhcpCheckTimeout
    # If the Management IP is in the private-IP/APIPA-IP range, wait till the timeout value interface gets a DHCP leased IP assigned
    while ($timeout -gt 0) {
        if (-not (Test-IsApipa -ipToCheck $CurrentManagementIp)) {
            $validIpFound = $true
            break
        }
        Write-Verbose -Message ('Management IP: {0}. Waiting for the base network to get a DHCP IP...' -f $CurrentManagementIp)
        $CurrentManagementIp, $infraPrefix, $dnsServer = Get-PrimaryInterface # infraPrefix and dnsServer are unused here
        Start-Sleep -Seconds 10
        $timeout -= 10
    }

    if (-not $validIpFound) {
        Write-Warning ('Unable to get a DHCP Mgmt IP assigned within {0} seconds. Managament IP: {1}' -f $dhcpCheckTimeout, $CurrentManagementIp)
    } else {
        Write-Verbose ('Found valid DHCP Mgmt IP {0} for the base network {1}' -f $CurrentManagementIp, $Global:BaseNetworkName)
    }

    return $CurrentManagementIp
}

function Setup-Network {
    param (
        [parameter(Mandatory = $true)] [string]
        $Action,

        [parameter(Mandatory = $true)] [string]
        $CniConfPath,

        [parameter(Mandatory = $true)] [string]
        $CniConfTemplatePath,

        [ValidateSet('L2Bridge', 'L2Tunnel', 'nat')]
        [parameter(Mandatory = $true)] [string]
        $NetworkType,

        [parameter(Mandatory = $false)] [string]
        $ManagementIp,

        [parameter(Mandatory = $false)] [string]
        $ManagementIpv6,

        [parameter(Mandatory = $false)] [string]
        $InfraPrefix,

        [parameter(Mandatory = $false)] [string]
        $InfraPrefixV6,

        [parameter(Mandatory = $false)] [System.Collections.ArrayList]
        $AddressPrefix = @('192.168.0.0/24'),

        [parameter(Mandatory = $false)] [System.Collections.ArrayList]
        $Gateway = @('192.168.0.1'),

        [parameter(Mandatory = $false)] [System.Collections.ArrayList]
        $localEndpoint = @('192.168.0.2'),

        [parameter(Mandatory = $false)] [bool]
        $withoutAcls = $false,

        [parameter(Mandatory = $false)] [string]
        $dnsServer = '168.63.129.16',

        [parameter(Mandatory = $true)] [string]
        $NetworkName,

        [parameter(Mandatory = $true)] [int]
        $dhcpCheckTimeout
    )

    Write-Host "Setting up network: $NetworkType"
    Validate-HNSRequirements
    Enable-HNSFeatures
    $CniType = ''
    $network = Get-HnsNetwork | Where-Object Name -EQ $NetworkName
    $CreateNetwork = $null -eq $network

    $ManagementIp = Wait-ForValidMgmtIp -NetworkType $NetworkType -CurrentManagementIp $ManagementIp `
                    -dhcpCheckTimeout $dhcpCheckTimeout

    if ($null -ne $network) {
        Write-Warning -Message ('Found previous network {0} of type {1}' -f $network.Name, $network.Type)
        if ($action -in 'Install', 'CleanInstall' -or $network.Type.ToLower() -ne $NetworkType) {
            Write-Verbose -Message 'Removing previous network'
            $network | Remove-HnsNetwork
            $CreateNetwork = $true
        } elseif ($action -eq 'Validate') {
            Wait-ForValidHnsMgmtIp -NetworkType $NetworkType -NetworkName $NetworkName `
            -requiredMgmtIp $ManagementIp -dhcpCheckTimeout $dhcpCheckTimeout
        }
    }

    if ($CreateNetwork) {
        Write-Verbose -Message ('Creating new network {0} of type {1}' -f $NetworkName, $NetworkType)
        $net = $null
        if ($NetworkType -eq 'nat') {
            $net = New-HnsNetwork -Type $NetworkType -name $NetworkName
            Write-Host "Created network '$($net.Name)' wit type '$($net.Type)' and ID '$($net.ID)'"

            try {
                $sub = $net.Subnets[0]
                Write-Verbose "Attempting to reserve gateway IP address: $($sub.GatewayAddress)"
                $ep = New-HnsEndpoint -Name ReserveGatewayIP -NetworkId $net.ID -IPAddress $sub.GatewayAddress
                Write-Verbose $ep
            } catch {
                Write-Warning $Error[0]
            }
            $CniType = 'nat'
        } elseif ($NetworkType -eq 'L2Bridge' -or $NetworkType -eq 'L2Tunnel') {
            $net = Setup-BridgeNetwork -networkType $NetworkType -networkName $NetworkName `
                -cleanup $false -AddressPrefix $AddressPrefix -Gateway $Gateway -localEndpoint $localEndpoint `
                -ManagementIp $ManagementIp
            $CniType = 'sdnbridge'
        }
    }

    if ($action -in 'Install', 'CleanInstall') {
        # create CNI config directory (eg, C:\ContainerPlat\cni\config) and parents, if need be
        $dir = Split-Path $CniConfPath
        Write-Verbose -Message "Creating CNI config directory: $dir"
        New-Item -Type Directory -Force -Path $dir > $null

        Write-Host "Writing CNI config file: $CniConfPath"
        Write-Host -Message 'Writing CNI config file'
        if ( [string]::IsNullOrEmpty($Script:CniArgs) ) {
            Write-Verbose "Using CNI template: $CniConfTemplatePath"
            if ($Global:enableDualStack) {
                $cniConfString = (Get-Content -Path $CniConfTemplatePath -Raw).
                Replace('{{NAME}}', $NetworkName).
                Replace('{{TYPE}}', $CniType).
                Replace('{{INFRA_PREFIX}}', $InfraPrefix).
                Replace('{{LOCAL_ENDPOINT}}', $ManagementIp).
                Replace('{{GATEWAY}}', $gateway[0]).
                Replace('{{DNSSERVER}}', $dnsServer).
                Replace('{{LOCAL_GW}}', $localEndpoint[0]).
                Replace('{{ADDRESS_PREFIX}}', $addressPrefix[0]).
                Replace('{{INFRA_PREFIX_IPV6}}', $InfraPrefixV6).
                Replace('{{LOCAL_ENDPOINT_IPV6}}', $ManagementIpv6).
                Replace('{{LOCAL_GW_IPV6}}', $localEndpoint[1]).
                Replace('{{ADDRESS_PREFIX_IPV6}}', $addressPrefix[1]).
                Replace('{{GATEWAYV6}}', $gateway[1])
            } else {
                $cniConfString = (Get-Content -Path $CniConfTemplatePath -Raw).
                Replace('{{NAME}}', $NetworkName).
                Replace('{{TYPE}}', $CniType).
                Replace('{{INFRA_PREFIX}}', $InfraPrefix).
                Replace('{{LOCAL_ENDPOINT}}', $ManagementIp).
                Replace('{{GATEWAY}}', $gateway[0]).
                Replace('{{DNSSERVER}}', $dnsServer).
                Replace('{{LOCAL_GW}}', $localEndpoint[0]).
                Replace('{{ADDRESS_PREFIX}}', $addressPrefix[0])
            }
            if ($WithoutAcls) {
                $cniConfObj = ConvertFrom-Json $cniConfString
                $cniConfObj.AdditionalArgs = @( $cniConfObj.AdditionalArgs | Where-Object { $_.Value.Type -ne 'ACL' })
                $cniConfString = ConvertTo-Json -Depth 10 $cniConfObj
            }
            $cniConfString | Out-File -FilePath $CniConfPath -Encoding ascii
        } else {
            $genCNIScriptLocation = [io.path]::Combine((Split-Path -Path $ScriptLocation), 'generateCNIConfig.ps1')
            Write-Verbose -Message ('Generating CNI Conf...')
            try {
                & $genCNIScriptLocation -CniConfPath $CniConfPath -CniArgs $Script:CniArgs
            } catch {
                Write-Warning -Message 'Failed to generate CNI conf with the current parameters'
                $network = Get-HnsNetwork | Where-Object Name -EQ $NetworkName
                if ($network) {
                    Write-Verbose -Message ('Cleaning up configured network {0} of type {1}' -f $network.Name, $network.Type)
                    $network | Remove-HnsNetwork
                }
                throw $_
            }
        }
    }
}

try {
    # Assumption: deploy.ps1, networkDeploy.ps1, generateCNIConfig.ps1 reside in same dir

    # Strict mode is inherited in the current and child scopes (but not propagated to parents):
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/set-strictmode
    #
    # deploy.ps1 sets strict mode, but deploy.exe does not, so disable it for consistency.
    Set-StrictMode -Off

    try {
        # if this is called from another PS script, then `$MyInvocation.Line` will the literall line value,
        # not include line continuations, and not fully expanded variables
        # see: https://github.com/PowerShell/PowerShell/pull/19027
        Write-Verbose "Invocation: $((Get-PSCallStack)[1].Position.Text.Trim())"
        Write-Verbose ('Arguments: ' +
            [string]($MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { '-' + $_.Key + ' ' + $_.Value }) + ' ' +
            [string]($MyInvocation.UnboundArguments.GetEnumerator() -join ' '))
    } catch {}

    # Default values
    $networkName = "ContainerPlat-$NetworkType" # NetworkType is a mandatory parameter
    $addressPrefix = @('192.168.0.0/24')
    $localEndpoint = @('192.168.0.2')
    $dnsServer = '168.63.129.16'
    $gateway = @('192.168.0.1')
    $dhcpCheckTimeout = $Script:DhcpTimeout

    $ManagementIp, $InfraPrefix, $dnsServer, $ipInterface = Get-PrimaryInterface

    #Check the CNI config file template to see if dual stack is enabled
    $content = Get-Content -Path $CniConfTemplatePath -Raw | ConvertFrom-Json
    if ($content.optionalFlags.PSobject.Properties.Name -contains 'enableDualStack') {
        $Global:enableDualStack = $content.optionalFlags.enableDualStack
    }

    Write-Verbose -Message "enableDualStack: $Global:enableDualStack"

    if ($Global:enableDualStack) {
        $addressPrefix += @('192::0/64')
        $localEndpoint += @('192::2')
        $gateway += @('192::1')
        $ManagementIpv6, $InfraPrefixIpv6 = Get-InfraDataV6 -ManagementIp $ManagementIp
    }

    if ( -not [string]::IsNullOrEmpty($Script:CniArgs) ) {
        # Decode CNI Args
        Write-Verbose -Message "Using CNI args: $Script:CniArgs"
        [string] $DecodedText = [System.Text.Encoding]::ascii.GetString([System.Convert]::FromBase64String($Script:CniArgs))
        Write-Verbose -Message "Decoded CNI args: $($DecodedText.Trim())"
        [System.Object] $cniArgs = $DecodedText | ConvertFrom-Json

        # Make modifications in CniArgs if required - ensure network created is in sync with the CNI Conf
        if ($cniArgs.psobject.Properties.name.Contains('Name')) {
            $networkName = $cniArgs.Name
        } else {
            $cniArgs | Add-Member -MemberType NoteProperty -Name 'Name' -Value $networkName
        }

        if ($cniArgs.psobject.Properties.name.Contains('Gateway')) {
            $gateway = @($cniArgs.Gateway)
        } else {
            $cniArgs | Add-Member -MemberType NoteProperty -Name 'Gateway' -Value $gateway
        }

        if ($cniArgs.psobject.Properties.name.Contains('Subnet')) {
            $addressPrefix = @($cniArgs.Subnet)
        } else {
            $cniArgs | Add-Member -MemberType NoteProperty -Name 'Subnet' -Value $addressPrefix
        }

        if ($cniArgs.psobject.Properties.name.Contains('DnsServers')) {
            $dnsServer = $cniArgs.DnsServers[0]
        } else {
            $cniArgs | Add-Member -MemberType NoteProperty -Name 'DnsServers' -Value @($dnsServer)
        }

        if ($cniArgs.psobject.Properties.name.Contains('ManagementIp')) {
            $ManagementIp = $cniArgs.ManagementIp
        } else {
            if ( [string]::IsNullOrEmpty($ManagementIp) ) {
                throw 'Fetching ManagementIP failed, please pass ManagementIP in CniArgs'
            }
            $cniArgs | Add-Member -MemberType NoteProperty -Name 'ManagementIp' -Value $ManagementIp
        }

        if ( [string]::IsNullOrEmpty($InfraPrefix) ) {
            $InfraPrefix = $addressPrefix
        }

        if ($cniArgs.psobject.Properties.name.Contains('InfraPrefix')) {
            $InfraPrefix = $cniArgs.InfraPrefix
        } else {
            $cniArgs | Add-Member -MemberType NoteProperty -Name 'InfraPrefix' -Value $InfraPrefix
        }

        if (($NetworkType -eq 'L2Bridge' -or $NetworkType -eq 'L2Tunnel') -and
            ($cniArgs.psobject.Properties.name.Contains('InfraParams'))) {
            $cniArgsInfraParams = $cniArgs.InfraParams
            if ($cniArgsInfraParams.psobject.Properties.name.Contains('DhcpEnabled')) {
                $dhcpCheckTimeout = $Script:DHCP_CHECK_TIMEOUT_MIN
                if ($cniArgsInfraParams.psobject.Properties.name.Contains('DhcpCheckTimeout')) {
                    if ((($cniArgsInfraParams.DhcpCheckTimeout -le $Script:DHCP_CHECK_TIMEOUT_MAX) -and ($cniArgsInfraParams.DhcpCheckTimeout -ge $Script:DHCP_CHECK_TIMEOUT_MIN)) -and (($cniArgsInfraParams.DhcpCheckTimeout % 10) -eq 0)) {
                        $dhcpCheckTimeout = $cniArgsInfraParams.DhcpCheckTimeout
                    } else {
                        throw ('DHCP Check timeout value should be between {0} and {1} seconds, and it should be a multiple of 10' -f $Script:DHCP_CHECK_TIMEOUT_MIN, $Script:DHCP_CHECK_TIMEOUT_MAX)
                    }
                }
            }
        }

        if ($Global:enableDualStack) {
            if ($cniArgs.psobject.Properties.name.Contains('GatewayV6')) {
                $gateway += @($cniArgs.GatewayV6)
            }

            if ($cniArgs.psobject.Properties.name.Contains('SubnetV6')) {
                $addressPrefix += @($cniArgs.SubnetV6)
            }

            if ($cniArgs.psobject.Properties.name.Contains('ManagementIpv6')) {
                $ManagementIpv6 = $cniArgs.ManagementIpv6
            } else {
                if ( [string]::IsNullOrEmpty($ManagementIpv6) ) {
                    Write-Verbose -Message 'Fetching ManagementIPv6 failed, please pass ManagementIPv6 in CniArgs'
                    throw $_
                }
                $cniArgs | Add-Member -MemberType NoteProperty -Name 'ManagementIpv6' -Value $ManagementIpv6
            }

            if ( [string]::IsNullOrEmpty($InfraPrefixIpv6) ) {
                $InfraPrefixIpv6 = $addressPrefix[1]
            }

            if ($cniArgs.psobject.Properties.name.Contains('InfraPrefixIpv6')) {
                $InfraPrefixIpv6 = $cniArgs.InfraPrefixIpv6
            } else {
                $cniArgs | Add-Member -MemberType NoteProperty -Name 'InfraPrefixIpv6' -Value $InfraPrefixIpv6
            }
        }

        # Encode CNI Args
        $cniArgsStr = ConvertTo-Json -Depth 50 $cniArgs
        Write-Verbose -Message "Updated CNI args: $($cniArgsStr.Trim())"
        [string] $EncodedText = [System.Convert]::ToBase64String([System.Text.Encoding]::ascii.GetBytes($cniArgsStr))
        $Script:CniArgs = $EncodedText
        Write-Verbose -Message ($Script:CniArgs)
    }

    $ScriptLocation = $MyInvocation.MyCommand.Path
    if ($Global:enableDualStack) {
        Setup-Network -Action $Action -CniConfPath $CniConfPath `
            -CniConfTemplatePath $CniConfTemplatePath -NetworkType $NetworkType `
            -withoutAcls $WithoutAcls -ManagementIp $ManagementIp -ManagementIpv6 $ManagementIpv6 -dnsServer $dnsServer `
            -NetworkName $networkName -AddressPrefix $addressPrefix -localEndpoint $localEndpoint -Gateway $gateway -InfraPrefixV6 $InfraPrefixIpv6 -InfraPrefix $InfraPrefix -dhcpCheckTimeout $dhcpCheckTimeout
    }
    else {
        Setup-Network -Action $Action -CniConfPath $CniConfPath `
            -CniConfTemplatePath $CniConfTemplatePath -NetworkType $NetworkType `
            -withoutAcls $WithoutAcls -ManagementIp $ManagementIp -dnsServer $dnsServer `
            -NetworkName $networkName -AddressPrefix $addressPrefix -localEndpoint $localEndpoint -Gateway $gateway -InfraPrefix $InfraPrefix -dhcpCheckTimeout $dhcpCheckTimeout
    }
}
catch {
    # not guaranteed that caller will propagate error stack trace, so log it here
    Write-Warning "Network deployment failed:`n$($_.ScriptStackTrace)"
    throw $_
}

# Cleanup Script variables
Remove-Variable -Name DHCP_CHECK_TIMEOUT_MIN -Scope Script
Remove-Variable -Name DHCP_CHECK_TIMEOUT_MAX -Scope Script
Remove-Variable -Name DHCP_CHECK_TIMEOUT_UNINITIALIZED -Scope Script
