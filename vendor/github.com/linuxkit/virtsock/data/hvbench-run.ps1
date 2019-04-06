#$MsgSzs = 1024, 2048
# 1518 and 9018 are Ethernet frame sizes for standard MTU and Jumbo frames
$MsgSzs = 8, 128, 512, 1024, 1518, 2048, 3072, 4096, 5120, 8192, 9018, 16384
$iter = 4
$idx = 0

# collect some info
$winver = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.FileVersion
$cpuinfo = (Get-WmiObject Win32_Processor).Name
$mem = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory
$mem = [Math]::Round(($mem/ 1GB),2)
$info = (docker info)
$linver = $info | select-string -pattern "Kernel"
$vmmem = $info | select-string -pattern "Memory"
$vmcpus = $info | select-string -pattern "CPUs"
Write-Output "# Windows Version: $winver"
Write-Output "# CPU: $cpuinfo"
Write-Output "# Memory: $mem GB"
Write-Output "# Linux $linver"
Write-Output "# Linux $vmmem"
Write-Output "# Linux $vmcpus"
Write-Output "#"

# get current path as something  we can use inside the VM
$CurDir = (& 'C:\Program Files\Git\usr\bin\cygpath.exe' $pwd)
$VMId = (Get-VM MobyLinuxVM).Id

# preload the docker nsenter image
docker pull justincormack/nsenter1 > $null
# Copy hvbench to a more convenient location
docker run --rm -ti --privileged --pid=host justincormack/nsenter1 /bin/cp $CurDir/hvbench /

# Can't -RedirectStandardError to $null. Create a dummy file...
$errout = ".\hvbench.err.txt"


#
# Bandwidth tests
#
# We have loopback mode, transmit from the VM and transmit to the
# VM. Then we have the receiver doing bulk receives into a large
# buffer or just calling receive with the message size. Finally, we
# can do blocking or non-blocking send() and recv() calls. Below we
# test the entire cross-product of these options.
Write-Output "# BW: Message sizes (in Bytes) vs Average Bandwidth (in Mb/s) + individual results"
Write-Output "# Index ${idx}: BW: Host loopback mode blocking (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -m $MsgSz"  -RedirectStandardError $errout
    Start-Sleep -s 1
    .\hvbench.exe -c loopback -B -m $MsgSz
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode poll() server (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p -m $MsgSz"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -m $MsgSz
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode poll() client (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -m $MsgSz"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -p -m $MsgSz
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode poll() both (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p -m $MsgSz"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -p -m $MsgSz
}

Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode blocking (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -m $MsgSz
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode poll() server (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -m $MsgSz
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode poll() client (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -p -m $MsgSz
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Host loopback mode poll() both (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p"  -RedirectStandardError $errout
    Start-Sleep -s 2
    .\hvbench.exe -c loopback -B -p -m $MsgSz
}


Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM blocking (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -m $MsgSz" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM poll() Linux (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -m $MsgSz" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -p -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM poll() Windows (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p -m $MsgSz" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM poll() both (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p -m $MsgSz" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -p -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}

Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM blocking (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM poll() Linux (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -p -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM poll() Windows (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit from VM poll() both (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -B -p" -RedirectStandardError $errout
        Start-Sleep -s 2
        $res = docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -B -p -m $MsgSz
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}


if ($linver.ToString() -match "4.4") {
    Write-Output "# BW: Transmit to VM skipped to Linux kernel $linver"
    return
}

# We only have 4.4 or later. For later kernels run the other direction to
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM blocking (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B -m $MsgSz
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM poll() Linux (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B -p -m $MsgSz
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM poll() Windows (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B -m $MsgSz
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -p -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM poll() both (msg recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B -p -m $MsgSz
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -p -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}

Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM blocking (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM poll() Linux (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B -p
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM poll() Windows (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -p -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: BW: Transmit to VM poll() both (bulk recv())"
$idx++
foreach ($MsgSz in $MsgSzs) {
    [int[]] $results = @()
    for($i=0; $i -lt $iter; $i++) {
        $svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -B -p
        Start-Sleep -s 2
        $res = .\hvbench.exe -c $VMId -B -p -m $MsgSz
        docker kill $svrid 2> $null
        $res = $res.split(' ')[1]
        $results += [convert]::ToInt32($res, 10)
    }
    $avg = ($results | Measure-Object -Average).average
    $tmp = $results -join ' '
    Write-Output "$MsgSz $avg $tmp"
}


#
# Connections tests
#
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: connect() from VM"
$idx++
# Start the server on the host and give it time to start
Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -C" -RedirectStandardError $errout
Start-Sleep -s 2
docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -C

Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: connect() to VM"
$idx++
# Start the server in the VM detached
$svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -C
Start-Sleep -s 2
.\hvbench.exe -c $VMId -C
docker kill $svrid 2> $null
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: connect() to VM with timeout"
$idx++
# Start the server in the VM detached
$svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -C
Start-Sleep -s 2
.\hvbench.exe -c $VMId -C -p
docker kill $svrid 2> $null

# create background load
start-job -scriptblock { while($true){} }
start-job -scriptblock { while($true){} }
start-job -scriptblock { while($true){} }
start-job -scriptblock { while($true){} }
start-job -scriptblock { while($true){} }
start-job -scriptblock { while($true){} }

Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: connect() from VM with load"
$idx++
# Start the server on the host and give it time to start
Start-Process -NoNewWindow -FilePath .\hvbench.exe -ArgumentList "-s -C" -RedirectStandardError $errout
Start-Sleep -s 2
docker run --rm --privileged --pid=host justincormack/nsenter1 /hvbench -c parent -C
Write-Output ""
Write-Output ""
Write-Output "# Index ${idx}: connect() to VM with load"
$idx++
# Start the server in the VM detached
$svrid = docker run -d --privileged --pid=host justincormack/nsenter1 /hvbench -s -C
Start-Sleep -s 2
.\hvbench.exe -c $VMId -C
docker kill $svrid 2> $null

# Kill background jobs
get-job | remove-job -force
