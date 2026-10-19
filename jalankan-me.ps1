$ErrorActionPreference = "Stop"
$collectionErrors = New-Object System.Collections.Generic.List[string]

function Get-CimValue {
    param(
        [string]$ClassName,
        [string]$PropertyName
    )

    try {
        return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop |
            ForEach-Object { $_.$PropertyName } |
            Where-Object { $_ })
    }
    catch {
        $message = "Membaca $ClassName gagal: $($_.Exception.Message)"
        $collectionErrors.Add($message)
        Write-Warning $message
        return @()
    }
}

$processors = @(Get-CimValue -ClassName "Win32_Processor" -PropertyName "Name")
$logicalProcessors = 0
try {
    $logicalProcessors = [int](Get-CimInstance -ClassName "Win32_Processor" -ErrorAction Stop |
        Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
}
catch {
    $message = "Membaca jumlah prosesor logis gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$memory = "Tidak tersedia"
try {
    $computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
    $memory = "{0:N1} GB" -f ($computerSystem.TotalPhysicalMemory / 1GB)
}
catch {
    $message = "Membaca RAM gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$operatingSystem = "Tidak tersedia"
$osVersion = "Tidak tersedia"
try {
    $os = Get-CimInstance -ClassName "Win32_OperatingSystem" -ErrorAction Stop
    $operatingSystem = $os.Caption
    $osVersion = "$($os.Version) (build $($os.BuildNumber))"
}
catch {
    $message = "Membaca versi Windows gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$networks = @()
try {
    foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up -or
            $adapter.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) {
            continue
        }

        $unicastAddresses = @($adapter.GetIPProperties().UnicastAddresses)
        $ipv4Addresses = @(
            $unicastAddresses |
                Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.Address.IPAddressToString }
        )
        $ipv6Addresses = @(
            $unicastAddresses |
                Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } |
                ForEach-Object { $_.Address.IPAddressToString }
        )
        $macBytes = $adapter.GetPhysicalAddress().GetAddressBytes()
        $mac = if ($macBytes.Length -gt 0) { [System.BitConverter]::ToString($macBytes) } else { "Tidak tersedia" }
        $networks += [PSCustomObject]@{
            name  = $adapter.Name
            ipv4  = $ipv4Addresses
            ipv6  = $ipv6Addresses
            mac   = $mac
        }
    }
}
catch {
    $message = "Membaca alamat IP/MAC gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$tcpPorts = @()
try {
    $tcpPorts = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique |
        Sort-Object { [int]$_ })
}
catch {
    $message = "Membaca port TCP gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$udpPorts = @()
try {
    $udpPorts = @(Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique |
        Sort-Object { [int]$_ })
}
catch {
    $message = "Membaca port UDP gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$disks = @()
try {
    $disks = @(Get-CimInstance -ClassName "Win32_LogicalDisk" -Filter "DriveType=3" -ErrorAction Stop |
        ForEach-Object {
            "{0} {1:N0} GB total, {2:N0} GB kosong" -f
                $_.DeviceID, ($_.Size / 1GB), ($_.FreeSpace / 1GB)
        })
}
catch {
    $message = "Membaca kapasitas penyimpanan gagal: $($_.Exception.Message)"
    $collectionErrors.Add($message)
    Write-Warning $message
}

$data = [PSCustomObject]@{
    computerName    = $env:COMPUTERNAME
    windowsUser     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    processors      = $processors
    cpuCores        = if ($logicalProcessors -gt 0) { [string]$logicalProcessors } else { "Tidak tersedia" }
    memory          = $memory
    graphics        = @(Get-CimValue -ClassName "Win32_VideoController" -PropertyName "Name")
    disks           = $disks
    networks        = $networks
    tcpPorts        = $tcpPorts
    udpPorts        = $udpPorts
    operatingSystem = $operatingSystem
    osVersion       = $osVersion
    architecture    = $env:PROCESSOR_ARCHITECTURE
    scannedAt       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    errors          = @($collectionErrors.ToArray())
}

$templatePath = Join-Path $PSScriptRoot "me.html"
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
    throw "File me.html tidak ditemukan di folder yang sama dengan skrip."
}

$template = [System.IO.File]::ReadAllText($templatePath)
$marker = "__DEVICE_DATA_BASE64__"
if (-not $template.Contains($marker)) {
    throw "Penanda data tidak ditemukan di me.html. Pastikan menggunakan file template yang benar."
}

$json = ConvertTo-Json -InputObject $data -Depth 6 -Compress
$encodedData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
$report = $template.Replace($marker, $encodedData)
$reportPath = Join-Path $env:TEMP "informasi-pc-report.html"
[System.IO.File]::WriteAllText($reportPath, $report, (New-Object System.Text.UTF8Encoding($false)))
Start-Process -FilePath $reportPath
Write-Host "Laporan PC dibuka di browser: $reportPath"
Write-Host "Laporan sementara berada di folder TEMP Windows; tidak ada database atau pengiriman data."
