$ErrorActionPreference = "Stop"
$collectionUrl = '__COLLECTION_URL__'
$collectionErrors = New-Object System.Collections.Generic.List[string]

$hostname = [System.Net.Dns]::GetHostName()
$windowsUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$platform = "Windows"
try {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $platform = "$($operatingSystem.Caption) $($operatingSystem.Version)"
}
catch {
    $collectionErrors.Add("Versi Windows tidak dapat dibaca: $($_.Exception.Message)")
}

$networkDetails = @()
$localIps = @()
foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($adapter.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up -or
        $adapter.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) {
        continue
    }

    $addresses = @(
        $adapter.GetIPProperties().UnicastAddresses |
            ForEach-Object { $_.Address.IPAddressToString }
    )
    $localIps += $addresses
    $macBytes = $adapter.GetPhysicalAddress().GetAddressBytes()
    if ($macBytes.Length -gt 0) {
        $networkDetails += [PSCustomObject]@{
            adapter = $adapter.Name
            mac     = [System.BitConverter]::ToString($macBytes)
        }
    }
}
$localIps = @($localIps | Select-Object -Unique)

$tcpPorts = @()
try {
    $tcpPorts = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique |
        ForEach-Object { [int]$_ } |
        Sort-Object)
}
catch {
    $collectionErrors.Add("Port TCP tidak dapat dibaca: $($_.Exception.Message)")
}

$udpPorts = @()
try {
    $udpPorts = @(Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique |
        ForEach-Object { [int]$_ } |
        Sort-Object)
}
catch {
    $collectionErrors.Add("Port UDP tidak dapat dibaca: $($_.Exception.Message)")
}

$publicIp = ""
try {
    $publicIp = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 8).ip
}
catch {
    $collectionErrors.Add("IP publik tidak dapat dibaca: $($_.Exception.Message)")
}

$payload = [PSCustomObject]@{
    device_name   = $hostname
    hostname      = $hostname
    windows_user  = $windowsUser
    platform      = $platform
    browser       = "Windows PowerShell collector"
    local_ips     = $localIps
    public_ip     = $publicIp
    mac_addresses = $networkDetails
    tcp_ports     = $tcpPorts
    udp_ports     = $udpPorts
    details       = [PSCustomObject]@{
        scanned_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        collector  = "PowerShell"
        adapters   = $networkDetails
        errors     = @($collectionErrors.ToArray())
    }
}

$json = ConvertTo-Json -InputObject $payload -Depth 6 -Compress
try {
    $null = Invoke-RestMethod -Uri $collectionUrl -Method Post -ContentType "application/json; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 20
}
catch {
    $message = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        $message = $_.ErrorDetails.Message
    }
    throw "Pengiriman data perangkat gagal: $message"
}

Write-Host "Data perangkat berhasil dikirim."
Write-Host "Hostname : $hostname"
Write-Host "User     : $windowsUser"
Write-Host "MAC      : $($networkDetails.Count) adapter"
Write-Host "TCP      : $($tcpPorts.Count) port"
Write-Host "UDP      : $($udpPorts.Count) port"
foreach ($message in $collectionErrors) {
    Write-Warning $message
}
