#Requires -Version 5.1

<#
.SYNOPSIS
    Automatically configure Windows desktop environment for corporate users.
    
.DESCRIPTION
    Configures wallpaper, lock screen, screensaver, Chrome as default browser,
    Outlook as default email client, and taskbar pins for corporate environment.
    
.PARAMETER Install
    Used during installation to create scheduled task (REQUIRES ADMIN)
    
.PARAMETER Configure
    Used during execution to apply desktop settings (NO ADMIN NEEDED)
    
.PARAMETER LogPath
    Where to write log files. Default: $env:TEMP\DesktopConfig.log
    
.EXAMPLE
    .\DesktopConfig.ps1 -Install
    Installs the scheduled task (run once as admin)
    
.EXAMPLE
    .\DesktopConfig.ps1 -Configure
    Applies configuration (automatically run at logon)
    
.NOTES
    Version: 2.2 - Enhanced registry logging and tracking
    Compatible: Windows 10 Pro, Windows 11 Pro
    Installation: Requires admin rights (one-time)
    Execution: Standard users (NO admin rights required)
#>

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Configure,
    [string]$LogPath = "$env:TEMP\DesktopConfig.log"
)

# =============================================================================
# CONFIGURATION VARIABLES - CUSTOMIZE FOR YOUR ENVIRONMENT
# =============================================================================

$Config = @{
    # IMAGE FILE LOCATIONS
    WallpaperPath = "C:\Ken\wallpaper\wallpaper.jpg"
    LockScreenPath = "C:\Ken\wallpaper\lockscreen.jpg"
    ScreensaverPath = "C:\Ken\wallpaper\screensaver.jpg"
    
    # SCREENSAVER SETTINGS
    ScreensaverTimeout = 600
    ScreensaverPasswordRequired = $true
    
    # APPLICATION PATHS
    ChromePath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
    OutlookPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\OUTLOOK.EXE"
    WordPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\WINWORD.EXE"
    ExcelPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\EXCEL.EXE"
    TeamsPath = "${env:LOCALAPPDATA}\Microsoft\WindowsApps\ms-teams.exe"
    
    # WEB APPLICATION URLS
    PlannerUrl = "https://planner.microsoft.com"
    
    # SYSTEM SETTINGS
    TaskName = "DesktopConfiguration"
    ScriptPath = $PSCommandPath
}

# Global registry change tracker
$script:RegistryChanges = @()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Write-RegistryChangeLog {
    param(
        [string]$Action,
        [string]$Path,
        [string]$Name,
        [string]$OldValue,
        [string]$NewValue,
        [string]$Type
    )
    
    $change = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action = $Action
        RegistryPath = $Path
        ValueName = $Name
        OldValue = $OldValue
        NewValue = $NewValue
        ValueType = $Type
    }
    
    $script:RegistryChanges += $change
    
    # Log to main log file
    $logMessage = "REGISTRY [$Action] Path: $Path | Name: $Name | Type: $Type"
    if ($Action -eq "MODIFIED") {
        $logMessage += " | Old: '$OldValue' | New: '$NewValue'"
    } elseif ($Action -eq "CREATED") {
        $logMessage += " | Value: '$NewValue'"
    }
    
    Write-Log $logMessage "REGISTRY"
}

function Export-RegistryChangeSummary {
    if ($script:RegistryChanges.Count -eq 0) {
        Write-Log "No registry changes were made during this session" "INFO"
        return
    }
    
    Write-Log "=== REGISTRY CHANGE SUMMARY ===" "INFO"
    Write-Log "Total registry modifications: $($script:RegistryChanges.Count)" "INFO"
    Write-Log "" "INFO"
    
    $groupedByAction = $script:RegistryChanges | Group-Object Action
    foreach ($group in $groupedByAction) {
        Write-Log "$($group.Name): $($group.Count) changes" "INFO"
    }
    
    Write-Log "" "INFO"
    Write-Log "Detailed Registry Changes:" "INFO"
    Write-Log "-------------------------" "INFO"
    
    foreach ($change in $script:RegistryChanges) {
        Write-Log "" "INFO"
        Write-Log "[$($change.Action)] $($change.Timestamp)" "INFO"
        Write-Log "  Path: $($change.RegistryPath)" "INFO"
        Write-Log "  Name: $($change.ValueName)" "INFO"
        Write-Log "  Type: $($change.ValueType)" "INFO"
        
        if ($change.Action -eq "MODIFIED") {
            Write-Log "  Old Value: '$($change.OldValue)'" "INFO"
            Write-Log "  New Value: '$($change.NewValue)'" "INFO"
        } elseif ($change.Action -eq "CREATED") {
            Write-Log "  Value: '$($change.NewValue)'" "INFO"
        }
    }
    
    Write-Log "" "INFO"
    Write-Log "=== END REGISTRY CHANGE SUMMARY ===" "INFO"
    
    # Export to CSV for easy review
    $csvPath = "$env:TEMP\DesktopConfig_RegistryChanges_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    try {
        $script:RegistryChanges | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
        Write-Log "Registry changes exported to: $csvPath" "SUCCESS"
    } catch {
        Write-Log "Failed to export registry changes to CSV: $($_.Exception.Message)" "WARNING"
    }
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsSystem {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
}

function Set-RegKey {
    param (
        $Path,
        $Name,
        $Value,
        [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
        $PropertyType = "DWord"
    )
    
    # Log the registry key path being accessed
    Write-Log "Accessing registry path: $Path" "DEBUG"
    
    # Create path if it doesn't exist
    if (-not $(Test-Path -Path $Path)) {
        try {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            Write-Log "Created registry path: $Path" "SUCCESS"
            Write-RegistryChangeLog -Action "PATH_CREATED" -Path $Path -Name "N/A" -OldValue "" -NewValue "" -Type "Path"
        } catch {
            Write-Log "Failed to create registry path: $Path - $($_.Exception.Message)" "ERROR"
            return
        }
    }
    
    # Check if value already exists
    $existingValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    
    if ($existingValue) {
        # Value exists - modify it
        $CurrentValue = $existingValue.$Name
        
        # Convert values to string for comparison
        $currentValueStr = if ($CurrentValue -is [array]) { $CurrentValue -join "," } else { $CurrentValue.ToString() }
        $newValueStr = if ($Value -is [array]) { $Value -join "," } else { $Value.ToString() }
        
        if ($currentValueStr -eq $newValueStr) {
            Write-Log "Registry value unchanged: $Path\$Name = $currentValueStr" "DEBUG"
            return
        }
        
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Log "Modified registry: $Path\$Name" "SUCCESS"
            Write-Log "  Changed from: '$currentValueStr' to: '$newValueStr'" "SUCCESS"
            
            Write-RegistryChangeLog -Action "MODIFIED" -Path $Path -Name $Name -OldValue $currentValueStr -NewValue $newValueStr -Type $PropertyType
        }
        catch {
            Write-Log "Failed to modify registry: $Path\$Name - $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        # Value doesn't exist - create it
        $newValueStr = if ($Value -is [array]) { $Value -join "," } else { $Value.ToString() }
        
        try {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Log "Created registry: $Path\$Name = '$newValueStr' (Type: $PropertyType)" "SUCCESS"
            
            Write-RegistryChangeLog -Action "CREATED" -Path $Path -Name $Name -OldValue "" -NewValue $newValueStr -Type $PropertyType
        }
        catch {
            Write-Log "Failed to create registry: $Path\$Name - $($_.Exception.Message)" "ERROR"
        }
    }
}

function Get-UserHives {
    param (
        [ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
        [String]$Type = "All",
        [String[]]$ExcludedUsers
    )
    
    $Patterns = switch ($Type) {
        "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
        "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
        "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
    }
    
    $UserProfiles = Foreach ($Pattern in $Patterns) { 
        Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
            Where-Object { $_.PSChildName -match $Pattern } | 
            Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
            @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
            @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
            @{Name = "Path"; Expression = { $_.ProfileImagePath } }
    }
    
    $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
}

# =============================================================================
# HASH CALCULATION FUNCTIONS (for Chrome default browser)
# =============================================================================

function Get-HexDateTime {
    $now = [DateTime]::Now
    $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $dateTime.ToFileTime()
    $hi = ($fileTime -shr 32)
    $low = ($fileTime -band 0xFFFFFFFFL)
    ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
}

function Get-Hash {
    param ([string]$BaseInfo)
    
    function Get-ShiftRight {
        param ([long]$iValue, [int]$iCount)
        if ($iValue -band 0x80000000) {
            Write-Output (($iValue -shr $iCount) -bxor 0xFFFF0000)
        }
        else {
            Write-Output ($iValue -shr $iCount)
        }
    }
    
    function Get-Long {
        param ([byte[]]$Bytes, [int]$Index = 0)
        Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
    }
    
    function Convert-Int32 {
        param ([long]$Value)
        [byte[]]$bytes = [BitConverter]::GetBytes($Value)
        return [BitConverter]::ToInt32($bytes, 0) 
    }
    
    [Byte[]]$bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
    $bytesBaseInfo += 0x00, 0x00  
    
    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [Byte[]]$bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
    
    $lengthBase = ($baseInfo.Length * 2) + 2 
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase 2) - 1
    $base64Hash = ""
    
    if ($length -gt 1) {
        $map = @{PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
            R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
        }
        
        $map.CACHE = 0
        $map.OUTHASH1 = 0
        $map.PDATA = 0
        $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
        $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
        $map.INDEX = Get-ShiftRight ($length - 2) 1
        $map.COUNTER = $map.INDEX + 1
        
        while ($map.COUNTER) {
            $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
            $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
            $map.PDATA = $map.PDATA + 8
            $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
            $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
            $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16)))
            $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
            $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
            $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
            $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
            $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
            $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
            $map.CACHE = ([long]$map.OUTHASH2)
            $map.COUNTER = $map.COUNTER - 1
        }
        
        [Byte[]]$outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        [byte[]]$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 0)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 4)
        
        $map.CACHE = 0
        $map.OUTHASH1 = 0
        $map.PDATA = 0
        $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
        $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
        $map.INDEX = Get-ShiftRight ($length - 2) 1
        $map.COUNTER = $map.INDEX + 1
        
        while ($map.COUNTER) {
            $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
            $map.PDATA = $map.PDATA + 8
            $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
            $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
            $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
            $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
            $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
            $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
            $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
            $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
            $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
            $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
            $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3) 
            $map.CACHE = ([long]$map.OUTHASH2)
            $map.COUNTER = $map.COUNTER - 1
        }
        
        $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 8)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 12)
        
        [Byte[]]$outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
        $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
        
        $buffer = [BitConverter]::GetBytes($hashValue1)
        $buffer.CopyTo($outHashBase, 0)
        $buffer = [BitConverter]::GetBytes($hashValue2)
        $buffer.CopyTo($outHashBase, 4)
        $base64Hash = [Convert]::ToBase64String($outHashBase) 
    }
    
    $base64Hash
}

# =============================================================================
# PIDL FUNCTIONS (for screensaver path encoding)
# =============================================================================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Shell32 {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern int SHParseDisplayName(string pszName, IntPtr pbc, out IntPtr ppidl, uint sfgaoIn, out uint psfgaoOut);
    
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern int ILGetSize(IntPtr pidl);
    
    [DllImport("ole32.dll")]
    public static extern void CoTaskMemFree(IntPtr pv);
}
"@ -ErrorAction SilentlyContinue

function Get-EncryptedPIDLStringFromPath {
    param ([string]$Path)
    
    try {
        $returnPIDL = [IntPtr]::Zero
        $result = [Shell32]::SHParseDisplayName($Path, [IntPtr]::Zero, [ref]$returnPIDL, 0, [ref][uint32]0)
        
        if ($result -ne 0) {
            throw "Failed to retrieve PIDL for path: $Path"
        }
        
        $SizeOfPIDL = [Shell32]::ILGetSize($returnPIDL)
        $ByteArray = New-Object byte[] $SizeOfPIDL
        [System.Runtime.InteropServices.Marshal]::Copy($returnPIDL, $ByteArray, 0, $SizeOfPIDL)
        $Base64EncodedString = [System.Convert]::ToBase64String($ByteArray)
        
        return $Base64EncodedString
    }
    catch {
        throw $_
    }
    finally {
        if ($returnPIDL -ne [IntPtr]::Zero) {
            [Shell32]::CoTaskMemFree($returnPIDL)
        }
    }
}

# =============================================================================
# DESKTOP CONFIGURATION FUNCTIONS
# =============================================================================

function Set-Wallpaper {
    param([string]$Path)
    
    try {
        if (Test-Path $Path) {
            Write-Log "Setting wallpaper from: $Path" "INFO"
            
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@ -ErrorAction SilentlyContinue
            
            $result = [Wallpaper]::SystemParametersInfo(0x0014, 0, $Path, 0x03)
            
            if ($result -ne 0) {
                Write-Log "Wallpaper set successfully: $Path" "SUCCESS"
                Write-Log "NOTE: Wallpaper is set via Windows API (SystemParametersInfo), not registry" "INFO"
                return $true
            }
        } else {
            Write-Log "Wallpaper file not found: $Path" "ERROR"
        }
    } catch {
        Write-Log "Failed to set wallpaper: $($_.Exception.Message)" "ERROR"
    }
    return $false
}

function Set-LockScreen {
    param([string]$Path)
    
    try {
        if (Test-Path $Path) {
            Write-Log "Setting lock screen image..." "INFO"
            
            if (Test-IsAdmin) {
                Write-Log "Setting lock screen system-wide with modification lock" "INFO"
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
                
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                    Write-Log "Created registry path: $regPath" "SUCCESS"
                    Write-RegistryChangeLog -Action "PATH_CREATED" -Path $regPath -Name "N/A" -OldValue "" -NewValue "" -Type "Path"
                }
                
                $oldValue = (Get-ItemProperty -Path $regPath -Name "LockScreenImagePath" -ErrorAction SilentlyContinue).LockScreenImagePath
                Set-ItemProperty -Path $regPath -Name "LockScreenImagePath" -Value $Path -Force
                
                Write-Log "Lock screen set system-wide: $Path" "SUCCESS"
                Write-RegistryChangeLog -Action $(if ($oldValue) {"MODIFIED"} else {"CREATED"}) -Path $regPath -Name "LockScreenImagePath" -OldValue $oldValue -NewValue $Path -Type "String"
                
                return $true
            } else {
                Write-Log "Setting lock screen for current user only" "INFO"
                
                try {
                    Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
                    [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
                    [Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
                    
                    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { 
                        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and 
                        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' 
                    })[0]
                    
                    $asTask = $asTaskGeneric.MakeGenericMethod([Windows.Storage.StorageFile])
                    $IStorageFile = $asTask.Invoke($null, @([Windows.Storage.StorageFile]::GetFileFromPathAsync($Path)))
                    $IStorageFile.Wait() | Out-Null
                    
                    $asTaskAction = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { 
                        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and 
                        !($_.IsGenericMethod) 
                    } | Select-Object -First 1
                    
                    $setImageTask = $asTaskAction.Invoke($null, @([Windows.System.UserProfile.LockScreen]::SetImageFileAsync($IStorageFile.Result)))
                    $setImageTask.Wait() | Out-Null
                    
                    Write-Log "Lock screen set for current user: $Path" "SUCCESS"
                    Write-Log "NOTE: Lock screen set via Windows Runtime API, not registry" "INFO"
                    return $true
                }
                catch {
                    Write-Log "Windows Runtime API failed, using registry fallback" "WARNING"
                    
                    $userRegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative"
                    if (!(Test-Path $userRegPath)) {
                        New-Item -Path $userRegPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $userRegPath -Name "LandscapeAssetPath" -Value $Path -Force
                    Set-ItemProperty -Path $userRegPath -Name "PortraitAssetPath" -Value $Path -Force
                    
                    Write-RegistryChangeLog -Action "CREATED" -Path $userRegPath -Name "LandscapeAssetPath" -OldValue "" -NewValue $Path -Type "String"
                    Write-RegistryChangeLog -Action "CREATED" -Path $userRegPath -Name "PortraitAssetPath" -OldValue "" -NewValue $Path -Type "String"
                    
                    Write-Log "Lock screen set for current user: $Path" "SUCCESS"
                    return $true
                }
            }
        } else {
            Write-Log "Lock screen file not found: $Path" "ERROR"
        }
    } catch {
        Write-Log "Failed to set lock screen: $($_.Exception.Message)" "ERROR"
    }
    return $false
}

function Set-Screensaver {
    param(
        [string]$ImagePath,
        [int]$TimeoutSeconds,
        [bool]$PasswordRequired = $true
    )
    
    try {
        Write-Log "Configuring screensaver settings..." "INFO"
        
        $ImageDirectory = $ImagePath
        if (Test-Path -Path $ImagePath -PathType Leaf) {
            $ImageDirectory = Split-Path -Path $ImagePath -Parent
        }
        
        $regPath = "HKCU:\Control Panel\Desktop"
        
        Set-RegKey -Path $regPath -Name "ScreenSaveActive" -Value "1" -PropertyType String
        Set-RegKey -Path $regPath -Name "ScreenSaveTimeOut" -Value $TimeoutSeconds.ToString() -PropertyType String
        Set-RegKey -Path $regPath -Name "SCRNSAVE.EXE" -Value "${env:SystemRoot}\System32\PhotoScreensaver.scr" -PropertyType String
        Set-RegKey -Path $regPath -Name "ScreenSaverIsSecure" -Value $(if ($PasswordRequired) { "1" } else { "0" }) -PropertyType String
        
        $ssRegPath = "HKCU:\Software\Microsoft\Windows Photo Viewer\Slideshow\Screensaver"
        if (!(Test-Path $ssRegPath)) {
            New-Item -Path $ssRegPath -Force | Out-Null
            Write-Log "Created registry path: $ssRegPath" "SUCCESS"
            Write-RegistryChangeLog -Action "PATH_CREATED" -Path $ssRegPath -Name "N/A" -OldValue "" -NewValue "" -Type "Path"
        }
        
        $EncryptedPIDL = Get-EncryptedPIDLStringFromPath $ImageDirectory
        Set-RegKey -Path $ssRegPath -Name "EncryptedPIDL" -Value $EncryptedPIDL -PropertyType String
        
        Write-Log "Screensaver configured: timeout=$TimeoutSeconds seconds, password=$PasswordRequired" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to configure screensaver: $($_.Exception.Message)" "ERROR"
    }
    return $false
}

function Set-DefaultBrowser {
    try {
        if (!(Test-Path $Config.ChromePath)) {
            Write-Log "Chrome not found at: $($Config.ChromePath)" "ERROR"
            return $false
        }
        
        Write-Log "Configuring Chrome as default browser (protocols only)..." "INFO"
        Write-Log "This will modify registry keys for: http, https, ftp protocols" "INFO"
        
        $UserProfiles = Get-UserHives -Type "All"
        $urlID = "ChromeHTML"
        $Protocols = "http", "https"
        
        foreach ($UserProfile in $UserProfiles) {
            Write-Log "Processing user: $($UserProfile.UserName) (SID: $($UserProfile.SID))" "INFO"
            
            $ProfileWasLoaded = $false
            
            if (!(Test-Path Registry::HKEY_USERS\$($UserProfile.SID))) {
                try {
                    Write-Log "Loading registry hive for $($UserProfile.UserName)" "INFO"
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden -ErrorAction Stop
                    $ProfileWasLoaded = $true
                } catch {
                    Write-Log "Could not load registry hive for $($UserProfile.UserName)" "WARNING"
                    continue
                }
            }
            
            $userExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
            $hexDateTime = Get-HexDateTime
            
            foreach ($Protocol in $Protocols) {
                try {
                    $ToBeHashed = "$Protocol$($UserProfile.SID)$urlID$hexDateTime$userExperience".ToLower()
                    $Hash = Get-Hash -BaseInfo $ToBeHashed
                    
                    $protocolPath = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
                    
                    Write-Log "Setting $Protocol protocol for $($UserProfile.UserName)" "INFO"
                    Set-RegKey -Path $protocolPath -Name "Hash" -Value $Hash -PropertyType String
                    Set-RegKey -Path $protocolPath -Name "ProgId" -Value $urlID -PropertyType String
                } catch {
                    Write-Log "Failed to set $Protocol for $($UserProfile.UserName)" "WARNING"
                }
            }
            
            if ($ProfileWasLoaded) {
                [gc]::Collect()
                Start-Sleep 1
                try {
                    Write-Log "Unloading registry hive for $($UserProfile.UserName)" "INFO"
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
                } catch {
                    Write-Log "Could not unload registry hive for $($UserProfile.UserName)" "WARNING"
                }
            }
        }
        
        Write-Log "Chrome default browser (protocols) configuration completed" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to set Chrome as default browser: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-DefaultBrowserFileAssociations {
    try {
        if (!(Test-Path $Config.ChromePath)) {
            Write-Log "Chrome not found at: $($Config.ChromePath)" "ERROR"
            return $false
        }
        
        Write-Log "Configuring Chrome file associations (.htm, .html)..." "INFO"
        Write-Log "This will modify registry keys for file extensions" "INFO"
        
        $UserProfiles = Get-UserHives -Type "All"
        $htmlID = "ChromeHTML"
        $Files = "htm", "html", "pdf", "xml"
        
        foreach ($UserProfile in $UserProfiles) {
            Write-Log "Processing file associations for: $($UserProfile.UserName)" "INFO"
            
            $ProfileWasLoaded = $false
            
            if (!(Test-Path Registry::HKEY_USERS\$($UserProfile.SID))) {
                try {
                    Write-Log "Loading registry hive for $($UserProfile.UserName)" "INFO"
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden -ErrorAction Stop
                    $ProfileWasLoaded = $true
                } catch {
                    Write-Log "Could not load registry hive for $($UserProfile.UserName)" "WARNING"
                    continue
                }
            }
            
            $userExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
            $hexDateTime = Get-HexDateTime
            
            foreach ($File in $Files) {
                try {
                    $ToBeHashed = ".$File$($UserProfile.SID)$htmlID$hexDateTime$userExperience".ToLower()
                    $Hash = Get-Hash -BaseInfo $ToBeHashed
                    
                    Write-Log "Setting .$File file association for $($UserProfile.UserName)" "INFO"
                    
                    # FileExts path - DELETE first using .NET Registry API, then recreate
                    $fileExtPath = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.$File\UserChoice"
                    
                    # Delete existing UserChoice key if it exists using .NET Registry API
                    try {
                        $parentPath = "$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.$File"
                        $hive = [Microsoft.Win32.Registry]::Users
                        $parent = $hive.OpenSubKey($parentPath, $true) # $true = writable
                        
                        if ($parent -ne $null) {
                            try {
                                $parent.DeleteSubKey('UserChoice', $false) # $false = don't throw if missing
                                Write-Log "Deleted UserChoice key for .$File using Registry API" "SUCCESS"
                            }
                            catch {
                                Write-Log "Could not delete UserChoice for .$File (may not exist or protected): $($_.Exception.Message)" "WARNING"
                            }
                            finally {
                                $parent.Close()
                            }
                        }
                        else {
                            Write-Log "Parent key for .$File does not exist, will create fresh" "INFO"
                        }
                    }
                    catch {
                        Write-Log "Failed to access registry for deletion of .$File $($_.Exception.Message)" "WARNING"
                    }
                    
                    # Now create fresh with Set-RegKey
                    Set-RegKey -Path $fileExtPath -Name "Hash" -Value $Hash -PropertyType String
                    Set-RegKey -Path $fileExtPath -Name "ProgId" -Value $htmlID -PropertyType String
                } catch {
                    Write-Log "Failed to set .$File for $($UserProfile.UserName): $($_.Exception.Message)" "WARNING"
                }
            }
            
            if ($ProfileWasLoaded) {
                [gc]::Collect()
                Start-Sleep 1
                try {
                    Write-Log "Unloading registry hive for $($UserProfile.UserName)" "INFO"
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
                } catch {
                    Write-Log "Could not unload registry hive for $($UserProfile.UserName)" "WARNING"
                }
            }
        }
        
        Write-Log "Chrome file associations configuration completed" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to set Chrome file associations: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-DefaultEmailClient {
    try {
        if (!(Test-Path $Config.OutlookPath)) {
            Write-Log "Outlook not found at: $($Config.OutlookPath)" "ERROR"
            return $false
        }
        
        $officeVersion = "15"
        $progID = "Outlook.URL.mailto.$officeVersion"
        Write-Log "Using ProgID: $progID" "INFO"
        Write-Log "Configuring Outlook as default email client..." "INFO"
        Write-Log "This will modify mailto protocol registry keys" "INFO"
        
        $UserProfiles = Get-UserHives -Type "All"
        
        foreach ($UserProfile in $UserProfiles) {
            Write-Log "Processing email client for: $($UserProfile.UserName)" "INFO"
            
            $ProfileWasLoaded = $false
            
            if (!(Test-Path Registry::HKEY_USERS\$($UserProfile.SID))) {
                try {
                    Write-Log "Loading registry hive for $($UserProfile.UserName)" "INFO"
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden -ErrorAction Stop
                    $ProfileWasLoaded = $true
                } catch {
                    Write-Log "Could not load registry hive for $($UserProfile.UserName)" "WARNING"
                    continue
                }
            }
            
            $userExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
            $hexDateTime = Get-HexDateTime
            
            try {
                $ToBeHashed = "mailto$($UserProfile.SID)$progID$hexDateTime$userExperience".ToLower()
                $Hash = Get-Hash -BaseInfo $ToBeHashed
                
                $mailtoPath = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\mailto\UserChoice"
                
                Set-RegKey -Path $mailtoPath -Name "Hash" -Value $Hash -PropertyType String
                Set-RegKey -Path $mailtoPath -Name "ProgId" -Value $progID -PropertyType String
                
                Write-Log "Set Outlook as default email for $($UserProfile.UserName)" "SUCCESS"
            } catch {
                Write-Log "Failed to set mailto for $($UserProfile.UserName): $($_.Exception.Message)" "WARNING"
            }
            
            if ($ProfileWasLoaded) {
                [gc]::Collect()
                Start-Sleep 1
                try {
                    Write-Log "Unloading registry hive for $($UserProfile.UserName)" "INFO"
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
                } catch {
                    Write-Log "Could not unload registry hive for $($UserProfile.UserName)" "WARNING"
                }
            }
        }
        
        Write-Log "Outlook default email client configuration completed" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to set Outlook as default email client: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-EdgeFromTaskbar {
    try {
        Write-Log "Removing Edge from taskbar..." "INFO"
        Write-Log "NOTE: Edge removal uses file deletion and COM verbs, not registry" "INFO"
        
        $edgeShortcuts = @(
            "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk",
            "$env:PUBLIC\Desktop\Microsoft Edge.lnk",
            "$env:USERPROFILE\Desktop\Microsoft Edge.lnk"
        )
        
        foreach ($shortcut in $edgeShortcuts) {
            if (Test-Path $shortcut) {
                try {
                    Remove-Item -Path $shortcut -Force -ErrorAction Stop
                    Write-Log "Removed Edge shortcut: $shortcut" "SUCCESS"
                } catch {
                    Write-Log "Could not remove Edge shortcut: $shortcut" "WARNING"
                }
            }
        }

        $appsFolder = (New-Object -ComObject Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items()
        $edgeApp = $appsFolder | Where-Object { $_.Name -eq "Microsoft Edge" }

        if ($edgeApp) {
            $verb = $edgeApp.Verbs() | Where-Object { $_.Name.Replace('&','') -match 'Unpin from taskbar' }
            if ($verb) {
                $verb.DoIt()
                Write-Log "Microsoft Edge was unpinned from the taskbar via COM verbs." "SUCCESS"
            } else {
                Write-Log "Unpin verb not available for Microsoft Edge (may already be unpinned)." "INFO"
            }
        } else {
            Write-Log "Microsoft Edge not found in AppsFolder (likely already removed)." "INFO"
        }

        Write-Log "Edge shortcuts processed (WebView2 preserved)" "SUCCESS"
        return $true

    } catch {
        Write-Log "Failed to remove Edge from taskbar: $($_.Exception.Message)" "ERROR"
    }
    return $false
}

function Set-TaskbarPins {
    try {
        Write-Log "Configuring taskbar pins..." "INFO"
        Write-Log "NOTE: Taskbar configuration uses XML import, not direct registry modification" "INFO"
        
        $XmlTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
    <CustomTaskbarLayoutCollection>
        <defaultlayout:TaskbarLayout>
            <taskbar:TaskbarPinList>
PINLISTXML
            </taskbar:TaskbarPinList>
        </defaultlayout:TaskbarLayout>
    </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

        $PinListContent = ""
        $PinnedApps = [System.Collections.Generic.List[String]]::new()
        
        if (Test-Path $Config.ChromePath) {
            Write-Log "Adding Chrome to taskbar" "INFO"
            $PinListContent += "                <taskbar:DesktopApp DesktopApplicationLinkPath=`"$($Config.ChromePath)`" />`r`n"
            $PinnedApps.Add("Chrome")
        } else {
            Write-Log "Chrome not found at: $($Config.ChromePath)" "WARNING"
        }
        
        if (Test-Path $Config.WordPath) {
            Write-Log "Adding Word to taskbar" "INFO"
            $PinListContent += "                <taskbar:DesktopApp DesktopApplicationLinkPath=`"$($Config.WordPath)`" />`r`n"
            $PinnedApps.Add("Word")
        } else {
            Write-Log "Word not found at: $($Config.WordPath)" "WARNING"
        }
        
        if (Test-Path $Config.ExcelPath) {
            Write-Log "Adding Excel to taskbar" "INFO"
            $PinListContent += "                <taskbar:DesktopApp DesktopApplicationLinkPath=`"$($Config.ExcelPath)`" />`r`n"
            $PinnedApps.Add("Excel")
        } else {
            Write-Log "Excel not found at: $($Config.ExcelPath)" "WARNING"
        }
        
        $teamsFound = $false
        if (Test-Path $Config.TeamsPath) {
            Write-Log "Adding Teams to taskbar" "INFO"
            $PinListContent += "                <taskbar:DesktopApp DesktopApplicationLinkPath=`"$($Config.TeamsPath)`" />`r`n"
            $PinnedApps.Add("Teams")
            $teamsFound = $true
        } else {
            $classicTeamsPath = "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe"
            if (Test-Path $classicTeamsPath) {
                Write-Log "Adding Teams (Classic) to taskbar" "INFO"
                $PinListContent += "                <taskbar:DesktopApp DesktopApplicationLinkPath=`"$classicTeamsPath`" />`r`n"
                $PinnedApps.Add("Teams")
                $teamsFound = $true
            }
        }
        
        if (-not $teamsFound) {
            try {
                $teamsAppx = Get-AppxPackage -Name "MSTeams" -ErrorAction SilentlyContinue
                if ($teamsAppx) {
                    $aumid = "MSTeams_8wekyb3d8bbwe!MSTeams"
                    Write-Log "Adding Teams (UWP) to taskbar" "INFO"
                    $PinListContent += "                <taskbar:UWA AppUserModelID=`"$aumid`" />`r`n"
                    $PinnedApps.Add("Teams")
                    $teamsFound = $true
                }
            } catch {
                Write-Log "Teams UWP app not found" "WARNING"
            }
        }
        
        if (-not $teamsFound) {
            Write-Log "Teams not found at any known location" "WARNING"
        }
        
        if (Test-Path $Config.ChromePath) {
            $plannerShortcut = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Planner.lnk"
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($plannerShortcut)
            $Shortcut.TargetPath = $Config.ChromePath
            $Shortcut.Arguments = "--app=$($Config.PlannerUrl)"
            $Shortcut.IconLocation = "$($Config.ChromePath),0"
            $Shortcut.Save()
            Write-Log "Created Planner shortcut: $plannerShortcut" "SUCCESS"
            
            $PinListContent += "                <taskbar:DesktopApp DesktopApplicationLinkPath=`"$plannerShortcut`" />`r`n"
            $PinnedApps.Add("Planner")
        }
        
        $XmlTemplate = $XmlTemplate -replace "PINLISTXML", $PinListContent.TrimEnd()
        
        $TempLayoutPath = "$env:Temp\layoutmodification$(Get-Random).xml"
        Write-Log "Creating layout file at: $TempLayoutPath" "INFO"
        Set-Content -Path $TempLayoutPath -Value $XmlTemplate -Force -Confirm:$false -ErrorAction Stop
        Write-Log "Successfully saved layout file" "SUCCESS"
        
        try {
            Import-StartLayout -LayoutPath $TempLayoutPath -MountPath "C:\" -Confirm:$false -ErrorAction Stop
            Write-Log "Successfully pinned $($PinnedApps -join ', ') to the taskbar" "SUCCESS"
        }
        catch {
            Write-Log "Failed to import taskbar layout: $($_.Exception.Message)" "ERROR"
            throw
        }
        finally {
            if (Test-Path $TempLayoutPath) {
                Remove-Item $TempLayoutPath -Force -ErrorAction SilentlyContinue
                Write-Log "Removed layout file" "INFO"
            }
        }
        
        Write-Log "Restarting Explorer to apply taskbar changes..." "INFO"
        Stop-Process -Name explorer -Force
        Start-Sleep -Seconds 2
        Write-Log "Explorer restarted successfully" "SUCCESS"
        
        return $true
    } catch {
        Write-Log "Failed to configure taskbar: $($_.Exception.Message)" "ERROR"
    }
    return $false
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

function Disable-UserChoiceProtection {
    Write-Log "Disabling User Choice Protection Driver..." "INFO"
    Write-Log "NOTE: UCPD changes require SYSTEM RESTART to take effect" "WARNING"
    
    try {
        Write-Log "  Modifying UCPD service registry..." "INFO"
        $ucpdServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"
        
        $oldStartValue = (Get-ItemProperty -Path $ucpdServicePath -Name "Start" -ErrorAction SilentlyContinue).Start
        Set-Service -Name UCPD -StartupType Disabled -ErrorAction Stop
        
        Write-RegistryChangeLog -Action "MODIFIED" -Path $ucpdServicePath -Name "Start" -OldValue $oldStartValue -NewValue "4" -Type "DWord"
        Write-Log "  UCPD service disabled successfully" "SUCCESS"
        
        Write-Log "  Disabling UCPD velocity scheduled task..." "INFO"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity" -ErrorAction Stop
        Write-Log "  UCPD velocity scheduled task disabled successfully" "SUCCESS"
        Write-Log "  NOTE: Task changes stored in Task Scheduler database, not registry" "INFO"
        
        Write-Log "User Choice Protection Driver has been disabled successfully!" "SUCCESS"
        Write-Log "⚠️  CRITICAL: Computer MUST be restarted for UCPD changes to take effect" "WARNING"
        return $true
    } catch {
        Write-Log "Failed to disable User Choice Protection: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Enable-UserChoiceProtection {
    Write-Log "Enabling User Choice Protection Driver..." "INFO"
    Write-Log "NOTE: UCPD changes require SYSTEM RESTART to take effect" "WARNING"
    
    try {
        Write-Log "  Modifying UCPD service registry..." "INFO"
        $ucpdServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"
        
        $oldStartValue = (Get-ItemProperty -Path $ucpdServicePath -Name "Start" -ErrorAction SilentlyContinue).Start
        Set-Service -Name UCPD -StartupType Automatic
        
        Write-RegistryChangeLog -Action "MODIFIED" -Path $ucpdServicePath -Name "Start" -OldValue $oldStartValue -NewValue "1" -Type "DWord"
        Write-Log "  UCPD service enabled successfully" "SUCCESS"
        
        Write-Log "  Enabling UCPD velocity scheduled task..." "INFO"
        Enable-ScheduledTask -TaskName "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity" -ErrorAction Stop
        Write-Log "  UCPD velocity scheduled task enabled successfully" "SUCCESS"
        Write-Log "  NOTE: Task changes stored in Task Scheduler database, not registry" "INFO"
        
        Write-Log "User Choice Protection Driver has been enabled successfully!" "SUCCESS"
        Write-Log "⚠️  CRITICAL: Computer MUST be restarted for UCPD changes to take effect" "WARNING"
        return $true
    } catch {
        Write-Log "Failed to Enabled User Choice Protection: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-LogonTask {
    try {
        Write-Log "Creating scheduled task for desktop configuration..." "INFO"
        Write-Log "NOTE: Task configuration stored in Task Scheduler database" "INFO"
        
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($Config.ScriptPath)`" -Configure"
        $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
        $taskPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Highest
        $task = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal
        
        Register-ScheduledTask -TaskName $Config.TaskName -InputObject $task -Force | Out-Null
        
        Write-Log "Logon task installed successfully for all users" "SUCCESS"
        Write-Log "Task Name: $($Config.TaskName)" "INFO"
        Write-Log "Trigger: At Logon (All Users)" "INFO"
        Write-Log "Script Path: $($Config.ScriptPath)" "INFO"
        return $true
    } catch {
        Write-Log "Failed to install logon task: $($_.Exception.Message)" "ERROR"
    }
    return $false
}

# =============================================================================
# IDEMPOTENCY FUNCTIONS
# =============================================================================

function Test-ConfigurationApplied {
    $markerPath = "$env:APPDATA\DesktopConfigApplied.marker"
    $currentVersion = "2.2"
    
    if (Test-Path $markerPath) {
        $existingVersion = Get-Content $markerPath -ErrorAction SilentlyContinue
        if ($existingVersion -eq $currentVersion) {
            Write-Log "Configuration marker found: Version $currentVersion already applied" "INFO"
            return $true
        } else {
            Write-Log "Configuration marker found but version mismatch: $existingVersion != $currentVersion" "INFO"
        }
    }
    return $false
}

function Set-ConfigurationMarker {
    $markerPath = "$env:APPDATA\DesktopConfigApplied.marker"
    $currentVersion = "2.2"
    Set-Content -Path $markerPath -Value $currentVersion -Force
    Write-Log "Configuration marker created: $markerPath (Version: $currentVersion)" "SUCCESS"
}

# =============================================================================
# MAIN CONFIGURATION FUNCTION
# =============================================================================

function Invoke-DesktopConfiguration {
    Write-Log "======================================" "INFO"
    Write-Log "Starting desktop configuration v2.2..." "INFO"
    Write-Log "======================================" "INFO"
    $startTime = Get-Date
    
    if (Test-ConfigurationApplied) {
        Write-Log "Configuration already applied and up to date - skipping" "INFO"
        return
    }
    
    $results = @()
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 1: Wallpaper Configuration ---" "INFO"
    $results += Set-Wallpaper -Path $Config.WallpaperPath
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 2: Lock Screen Configuration ---" "INFO"
    $results += Set-LockScreen -Path $Config.LockScreenPath
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 3: Screensaver Configuration ---" "INFO"
    $results += Set-Screensaver -ImagePath $Config.ScreensaverPath -TimeoutSeconds $Config.ScreensaverTimeout
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 4: Chrome Default Browser (Protocols) ---" "INFO"
    $results += Set-DefaultBrowser
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 5: Chrome File Associations ---" "INFO"
    $results += Set-DefaultBrowserFileAssociations
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 6: Outlook Default Email Client ---" "INFO"
    $results += Set-DefaultEmailClient
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 7: Remove Edge from Taskbar ---" "INFO"
    $results += Remove-EdgeFromTaskbar
    
    Write-Log "" "INFO"
    Write-Log "--- STEP 8: Configure Taskbar Pins ---" "INFO"
    $results += Set-TaskbarPins
    
    Write-Log "" "INFO"
    Set-ConfigurationMarker
    
    Start-Sleep -Seconds 3
    Enable-UserChoiceProtection
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    $successCount = ($results | Where-Object {$_ -eq $true}).Count
    $totalCount = $results.Count
    
    Write-Log "" "INFO"
    Write-Log "======================================" "INFO"
    Write-Log "Configuration Summary" "INFO"
    Write-Log "======================================" "INFO"
    Write-Log "Total Tasks: $totalCount" "INFO"
    Write-Log "Successful: $successCount" "INFO"
    Write-Log "Failed: $($totalCount - $successCount)" "INFO"
    Write-Log "Duration: $([math]::Round($duration, 2)) seconds" "INFO"
    Write-Log "======================================" "INFO"
    
    if ($duration -gt 30) {
        Write-Log "WARNING: Configuration took longer than 30 seconds ($([math]::Round($duration, 2)) s)" "WARNING"
    }
    
    Write-Log "" "INFO"
    Export-RegistryChangeSummary
}

# =============================================================================
# MAIN SCRIPT EXECUTION
# =============================================================================

try {
    Write-Log "==========================================" "INFO"
    Write-Log "Desktop Configuration Script Started" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "User: $env:USERNAME" "INFO"
    Write-Log "Computer: $env:COMPUTERNAME" "INFO"
    Write-Log "Domain: $env:USERDOMAIN" "INFO"
    Write-Log "Admin Rights: $(Test-IsAdmin)" "INFO"
    Write-Log "System Account: $(Test-IsSystem)" "INFO"
    Write-Log "Log File: $LogPath" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "" "INFO"
    
    if ($Install) {
        Write-Log "MODE: Installation" "INFO"
        Write-Log "" "INFO"
        
        if (Test-IsAdmin) {
            Write-Host ""
            Write-Host "=== STEP 1: DISABLING USER CHOICE PROTECTION ===" -ForegroundColor Cyan
            Write-Host ""
            
            $ucpdResult = Disable-UserChoiceProtection
            
            if (-not $ucpdResult) {
                Write-Host ""
                Write-Host "[WARNING] Failed to disable User Choice Protection Driver!" -ForegroundColor Yellow
                Write-Host "Chrome default browser settings may not persist properly." -ForegroundColor Yellow
                Write-Host ""
                $continue = Read-Host "Do you want to continue installation anyway? (y/n)"
                if ($continue -notlike "y*") {
                    Write-Log "Installation cancelled by user" "INFO"
                    Export-RegistryChangeSummary
                    exit 0
                }
            }
            
            Write-Host ""
            Write-Host "=== STEP 2: INSTALLING SCHEDULED TASK ===" -ForegroundColor Cyan
            Write-Host ""
            
            $installResult = Install-LogonTask
            
            if ($installResult) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Green
                Write-Host "  INSTALLATION COMPLETED SUCCESSFULLY  " -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
                Write-Host ""
                Write-Log "Installation completed successfully" "SUCCESS"
                
                Write-Host "IMPORTANT: RESTART REQUIRED" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "The User Choice Protection Driver has been disabled." -ForegroundColor White
                Write-Host "You MUST restart the computer for all changes to take effect." -ForegroundColor White
                Write-Host ""
                Write-Host "After restart:" -ForegroundColor Cyan
                Write-Host "  • Chrome default browser settings will work properly" -ForegroundColor White
                Write-Host "  • Chrome file associations (.pdf, .html) will be set" -ForegroundColor White
                Write-Host "  • Configuration will run automatically at user logon" -ForegroundColor White
                Write-Host "  • All desktop settings will be applied to users" -ForegroundColor White
                Write-Host ""
                
                Export-RegistryChangeSummary
                
                $restart = Read-Host "Do you want to restart the computer now? (y/n)"
                if ($restart -like "y*") {
                    Write-Host ""
                    Write-Host "Restarting computer in 10 seconds..." -ForegroundColor Yellow
                    Write-Host "Press Ctrl+C to cancel" -ForegroundColor Yellow
                    Start-Sleep -Seconds 10
                    Restart-Computer -Force
                } else {
                    Write-Host ""
                    Write-Host "Please restart the computer manually as soon as possible." -ForegroundColor Yellow
                    Write-Host ""
                }
                
                exit 0
            } else {
                Write-Log "Installation failed. Check error messages above." "ERROR"
                Export-RegistryChangeSummary
                exit 1
            }
        } else {
            Write-Log "Installation requires administrator rights" "ERROR"
            Write-Host ""
            Write-Host "[ERROR] Administrator rights required!" -ForegroundColor Red
            Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
            Write-Host ""
            exit 1
        }
    } 
    elseif ($Configure) {
        Write-Log "MODE: Configuration" "INFO"
        Write-Log "" "INFO"
        
        Invoke-DesktopConfiguration
        
        Write-Log "" "INFO"
        Write-Log "Configuration mode completed successfully" "SUCCESS"
        
        Export-RegistryChangeSummary
        exit 0
    } 
    else {
        Write-Log "MODE: Usage Information" "INFO"
        Write-Host ""
        Write-Host "Desktop Configuration Script" -ForegroundColor Cyan
        Write-Host "==================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage:" -ForegroundColor Yellow
        Write-Host "  Install (requires admin):    .\DesktopConfig.ps1 -Install" -ForegroundColor White
        Write-Host "  Configure (automatic):       .\DesktopConfig.ps1 -Configure" -ForegroundColor White
        Write-Host ""
        Write-Host "Configuration includes:" -ForegroundColor Yellow
        Write-Host "  • Wallpaper and lock screen" -ForegroundColor White
        Write-Host "  • Company screensaver" -ForegroundColor White
        Write-Host "  • Chrome as default browser (HTTP/HTTPS/FTP protocols)" -ForegroundColor White
        Write-Host "  • Chrome file associations (.pdf, .html,)" -ForegroundColor White
        Write-Host "  • Outlook as default email client" -ForegroundColor White
        Write-Host "  • Taskbar pins (Chrome, Word, Excel, Teams, Planner)" -ForegroundColor White
        Write-Host "  • Edge association removal" -ForegroundColor White
        Write-Host ""
        Write-Host "Logs and Registry Changes:" -ForegroundColor Yellow
        Write-Host "  Main Log:          $LogPath" -ForegroundColor White
        Write-Host "  Registry CSV:      $env:TEMP\DesktopConfig_RegistryChanges_*.csv" -ForegroundColor White
        Write-Host ""
        exit 0
    }
    
} catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    Export-RegistryChangeSummary
    exit 1
}

Write-Log "" "INFO"
Write-Log "Script completed successfully" "SUCCESS"
Write-Log "==========================================" "INFO"
Export-RegistryChangeSummary
exit 0