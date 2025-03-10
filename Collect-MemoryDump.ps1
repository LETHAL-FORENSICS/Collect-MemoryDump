# Collect-MemoryDump v1.1.0
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2019-2025 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:		  https://lethal-forensics.com/
# @date:	  2025-03-10
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
# 7-Zip 24.09 Standalone Console (2024-11-29)
# https://www.7-zip.org/download.html
#
# Belkasoft Live RAM Capturer (2018-10-22)
# https://belkasoft.com/ram-capturer
#
# MAGNET DumpIt for Windows (2023-01-17) --> Comae-Toolkit-v20230117
# https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/
#
# Magnet Encrypted Disk Detector v3.1.0 (2022-06-19)
# Requirements: .NET v4.0.30319
# https://www.magnetforensics.com/resources/encrypted-disk-detector/
#
# Magnet RAM Capture v1.2.0 (2019-07-24)
# https://www.magnetforensics.com/resources/magnet-ram-capture/
#
# Magnet RESPONSE v1.7.1 (2024-09-07)
# Requirements: .NET v4.0.30319
# https://www.magnetforensics.com/resources/magnet-response/
#
# PsLoggedOn v1.35 (2016-06-29)
# https://docs.microsoft.com/de-de/sysinternals/downloads/psloggedon
#
# WinPMEM 4.0 RC2 (2020-10-13)
# https://github.com/Velocidex/WinPmem/releases
#
#
#############################################################################################################################################################################################

# Hash Values (Whitelisting)

# 7za.exe                    MD5: 86D2E800B12CE5DA07F9BD2832870577   SHA1: FBA06CFB1D2A59D12F3495B301501D4B1D52D7DB   SHA256: 223B873C50380FE9A39F1A22B6ABF8D46DB506E1C08D08312902F6F3CD1F7AC3
# DumpIt.exe (ARM64)         MD5: 4B39D63B86FFE39BBAE0415C400003C7   SHA1: E08DE257DB9EE0D2AEC8A34433883B025020227B   SHA256: 13BCA00D0042748780B761FB93768754DFD96F48944E6CEC75618CAD93B3B5D5
# DumpIt.exe (x64)           MD5: 0F10DA3A5EB49D17D73D8E195FE32F85   SHA1: 95F7B26CD15170A3043D6D1F049B2A88FB7A5C5F   SHA256: 6A484C1DB7718949C7027ABDE97E164C7E7E4E4214E3E29FE48AC4364C0CD23C
# DumpIt.exe (x86)           MD5: 586C57AD0EEA179FCAE4B8BA117F2AB9   SHA1: 31F4ECD04D5A94437A98D09435A2CEAC7DFD57DC   SHA256: F4F353821178BDAF3E29B49DB6E6D80C543081AC7A4312E5FDB5583B96815839
# EDDv310.exe                MD5: EE4E8097DA5DC038EC3C9B2CB9DB4700   SHA1: 94D250ECA8CD73FB62541E59EC9E6191F71F22A2   SHA256: DE3FC8F41D498D2108DFD52DE8E6200C6271BB45F3FBD6DA5E4C7C648A5BB5B8
# MagnetRESPONSE.exe         MD5: 2A3BA98713A243F90CD0582C64F13CFB   SHA1: AE4E55C15B338229697485AB6154E6E36CA8539D   SHA256: 341A42C9D95855CC62456EF30ECAD14F922E11CBC8374E83B4F758A6DBECC9DE
# MRCv120.exe                MD5: 51D286BDF58359417A28E3132ABA957F   SHA1: 6FA7C189B736808C66C82CCF5F4AAA11F995C95A   SHA256: 72DC1BA6DDC9D572D70A194EBDF6027039734ECEE23A02751B0B3B3C4EA430DE
# PsLoggedon.exe             MD5: E3EA271E748CCDAD6A6D3E692D6F337E   SHA1: F02E06BC439A28AAD6DD957DF8D0022F22798A09   SHA256: D689CB1DBD2E4C06CD15E51A6871C406C595790DDCDCD7DC8D0401C7183720EF
# PsLoggedon64.exe           MD5: 07ED30D2343BF8914DAAED872B681118   SHA1: 1F5B5E40C420F64AA8E8DE471367E3DECC9763CD   SHA256: FDADB6E15C52C41A31E3C22659DD490D5B616E017D1B1AA6070008CE09ED27EA
# RamCapture64.exe           MD5: E331F960CDBA675DEA9218EFDED56A5F   SHA1: 8BD76FB052A10A3EDA7F85993B4B6766C517C646   SHA256: 3F934019C46763B518C90E9D66088A301BD50FFC7F90D447FF1B54AF96AB9E4E
# RamCapture.exe             MD5: FCA60980F235B4EFB3C3119EF4584FFF   SHA1: 465F8F1BEFC212700EA1A71F5CE6F6899A707612   SHA256: 6E2C3E0CE3ABBD8D027E77D210891F2F835400856F36BB70AEA47598F1C5B131
# winpmem_mini_x64_rc2.exe   MD5: 9DD3160679832165738BFABD7279ACEB   SHA1: E460CA732204740674C27073E0FA478F334420FC   SHA256: A4D516B6FCAF3B5B1D4EE709CE86F8EABF1D8028B3A83101479B7568B933D21B
# winpmem_mini_x86.exe       MD5: C2BC7851F966BC39068345FB24BC8740   SHA1: F552A8C22D589471BE582BF884AA5624C967760B   SHA256: DC6A82FC6CFDA792D3182E07DE10ADBFBA42BF336EF269DBC40732C4B2AE052C

#############################################################################################################################################################################################

#region Arguments

Function HelpMessage
{
    Write-Output ""
    Write-Output "Collect-MemoryDump v1.1.0 - Automated Creation of Windows Memory Snapshots for DFIR"
    Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
    Write-Output ""

    Write-Output "Usage: .\Collect-MemoryDump.ps1 [-Tool] [--Pagefile] [--Triage]"
    Write-Output ""
    Write-Output "Tools:"
    Write-Output "-Comae        Memory Snapshot will be collected w/ DumpIt (Microsoft Crash Dump)"
    Write-Output "-DumpIt       Memory Snapshot will be collected w/ DumpIt (Raw Physical Memory Dump)"
    Write-Output "-RamCapture   Memory Snapshot will be collected w/ Magnet Ram Capture (Raw Physical Memory Dump)"
    Write-Output "-WinPMEM      Memory Snapshot will be collected w/ WinPMEM (Raw Physical Memory Dump)"
    Write-Output "-Belkasoft    Memory Snapshot will be collected w/ Belkasoft Live Ram Capturer (Raw Physical Memory Dump)"
    Write-Output ""
    Write-Output "Optional:"
    Write-Output "--Pagefile    In addition, Pagefile(s) will be collected w/ Magnet RESPONSE"
    Write-Output "--Triage      In addition, Forensic Artifacts will be collected w/ Magent RESPONSE"
    Write-Output ""
    Write-Output "Examples:"
    Write-Output ".\Collect-MemoryDump.ps1 -Comae"
    Write-Output ".\Collect-MemoryDump.ps1 -DumpIt"
    Write-Output ".\Collect-MemoryDump.ps1 -WinPMEM"
    Write-Output ".\Collect-MemoryDump.ps1 -RamCapture"
    Write-Output ".\Collect-MemoryDump.ps1 -Belkasoft"
    Write-Output ".\Collect-MemoryDump.ps1 -DumpIt --Pagefile"
    Write-Output ".\Collect-MemoryDump.ps1 -WinPMEM --Pagefile"
    Write-Output ".\Collect-MemoryDump.ps1 -DumpIt --Pagefile --Triage"
    Write-Output ".\Collect-MemoryDump.ps1 -Comae --Triage"
    Write-Output ""
    Exit
}

# Arguments

# Check if an argument was provided
if($Args.Count -eq 0)
{
    HelpMessage
}

# Check if more than 3 arguments were provided
if($Args.Count -gt 3)
{
    HelpMessage
}

# Validate $Args[0]
if ($Args[0])
{
    $Tool = ($Args[0] | Out-String).Trim()

    if (($Tool -ne "-DumpIt") -and ($Tool -ne "-RamCapture") -and ($Tool -ne "-WinPMEM") -and ($Tool -ne "-Comae") -and ($Tool -ne "-Belkasoft"))
    {
        HelpMessage
    }
}

# Validate $Args[1]
if ($Args[1])
{
    $Argument1 = ($Args[1] | Out-String).Trim()

    if (($Argument1 -ne "--Pagefile") -and ($Argument1 -ne "--Triage"))
    {
        HelpMessage
    }

    if ($Argument1 -eq "--Pagefile")
    {
        $Pagefile = $Argument1
    }

    if ($Argument1 -eq "--Triage")
    {
        $Triage = $Argument1
    }
}

# Validate $Args[2]
if ($Args[2])
{
    $Argument2 = ($Args[2] | Out-String).Trim()

    if (($Argument2 -ne "--Pagefile") -and ($Argument2 -ne "--Triage"))
    {
        HelpMessage
    }

    if ($Argument2 -eq "--Pagefile")
    {
        $Pagefile = $Argument2
    }

    if ($Argument2 -eq "--Triage")
    {
        $Triage = $Argument2
    }
}

#endregion Arguments

#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Acquisition date (ISO 8601)
$Date = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss") # YYYY-MM-DDThh:mm:ss
$Timestamp = $Date -replace ":", "" # YYYY-MM-DDThhmmss

# Output Directory
$OUTPUT_FOLDER = "$SCRIPT_DIR\$env:COMPUTERNAME\$Timestamp-Collect-MemoryDump"

# Logfile Directory
$LOG_DIR = "$SCRIPT_DIR\$env:COMPUTERNAME"

# Tools

# 7-Zip
$7za = "$SCRIPT_DIR\Tools\7-Zip\7za.exe"

# Belkasoft Live RAM Capturer

# x64
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
{
    $Belkasoft = "$SCRIPT_DIR\Tools\RamCapturer\x64\RamCapture64.exe"
}

# x86
if ($env:PROCESSOR_ARCHITECTURE -eq "x86")
{
    $Belkasoft = "$SCRIPT_DIR\Tools\RamCapturer\x86\RamCapture.exe"
}

# DumpIt

# ARM64
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
{
    $DumpIt = "$SCRIPT_DIR\Tools\DumpIt\ARM64\DumpIt.exe"
}

# x64
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
{
    $DumpIt = "$SCRIPT_DIR\Tools\DumpIt\x64\DumpIt.exe"
}

# x86
if ($env:PROCESSOR_ARCHITECTURE -eq "x86")
{
    $DumpIt = "$SCRIPT_DIR\Tools\DumpIt\x86\DumpIt.exe"
}

# Magnet Forensics Encrypted Disk Detector (EDD)
$EDD = "$SCRIPT_DIR\Tools\EDD\EDDv310.exe"

# Magnet RAM Capture (MRC)
$MRC = "$SCRIPT_DIR\Tools\MRC\MRCv120.exe"

# Magnet RESPONSE
$MagnetRESPONSE = "$SCRIPT_DIR\Tools\MagnetRESPONSE\MagnetRESPONSE.exe"

# PsLoggedOn

# x64
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
{
    $PsLoggedOn = "$SCRIPT_DIR\Tools\PsLoggedOn\PsLoggedon64.exe"
}

# x86
if ($env:PROCESSOR_ARCHITECTURE -eq "x86")
{
    $PsLoggedOn = "$SCRIPT_DIR\Tools\PsLoggedOn\PsLoggedon.exe"
}

# WinPMEM

# x64
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
{
    $WinPMEM = "$SCRIPT_DIR\Tools\WinPMEM\winpmem_mini_x64_rc2.exe"
}

# x86
if ($env:PROCESSOR_ARCHITECTURE -eq "x86")
{
    $WinPMEM = "$SCRIPT_DIR\Tools\WinPMEM\winpmem_mini_x86.exe"
}

# Secure Archive Password
$PASSWORD = "IncidentResponse"

#endregion Declarations

#############################################################################################################################################################################################

#region Header

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Output "[Error] This PowerShell script must be run with admin rights."
    Exit
}

# Check if the PowerShell script is being run in Windows PowerShell ISE
if ($psISE)
{
    Write-Output "[Error] This PowerShell script must be run in Windows PowerShell."
    Exit
}

# Check if the PowerShell script is being run in PowerShell Core
if ($PSVersionTable.PSEdition -eq "Core")
{
    Write-Output "[Error] This PowerShell script must be run in Windows PowerShell."
    Exit
}

# Windows Title
$script:DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Collect-MemoryDump v1.1.0 - Automated Creation of Windows Memory Snapshots for DFIR"

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

# Function Get-FileSize
Function script:Get-FileSize() {
    Param ([long]$Length)
    if ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    elseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    elseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    elseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    elseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    else {""}
}

# Function Test-RegistryValue
Function Test-RegistryValue
{
    param([string]$Path,[string]$Value)
    $ValueExist = $null -ne (Get-ItemProperty $Path).$Value
    Return $ValueExist
}

# Get Start Time
$StartTime = (Get-Date)

# Creating Output Directory
New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

Write-Output "" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "$Logo" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# Header
Write-Output "Collect-MemoryDump v1.1.0 - Automated Creation of Windows Memory Snapshots for DFIR"
Write-Output "$([char]0x00A9) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

Write-Output "Collect-MemoryDump v1.1.0 - Automated Creation of Windows Memory Snapshots for DFIR" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "$([char]0x00A9) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# Acquisition date (ISO 8601)
$AcquisitionStartTime = $Date -replace "T", " " # YYYY-MM-DD hh:mm:ss
Write-Output "Acquisition date: $AcquisitionStartTime UTC"
Write-Output ""

Write-Output "Acquisition date: $AcquisitionStartTime UTC" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# Hostname
Write-Output "[Info]  Host Name: $env:COMPUTERNAME"
Write-Output "[Info]  Host Name: $env:COMPUTERNAME" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

#endregion Header

#############################################################################################################################################################################################

#region Pagefile

# Note: Save the pagefile.sys file immediately after capturing RAM.

Function Get-Pagefile
{
    # Magnet RESPONSE
    if (Test-Path "$MagnetRESPONSE") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$MagnetRESPONSE" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        if ($MD5 -eq "2A3BA98713A243F90CD0582C64F13CFB")
        {
            # PageFileInfo
            New-Item "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo" -ItemType Directory -Force | Out-Null

            # AutomaticManagedPagefile
            [string]$AutomaticManagedPagefile = (Get-WmiObject -Class Win32_ComputerSystem -Namespace 'root\cimv2' | Select-Object AutomaticManagedPagefile).AutomaticManagedPagefile

            # Automatically manage paging file size for all drives
            if ($AutomaticManagedPagefile -eq "True")
            {
                Write-Output "[Info]  AutomaticManagedPagefile: True (Default: True)" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\AutomaticManagedPagefile.txt"
                Write-Output "        Note: The automatic system page file management is enabled for all drives." | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\AutomaticManagedPagefile.txt" -Append
            }

            # Custom size, System managed size, No paging file
            if ($AutomaticManagedPagefile -eq "False")
            {
                Write-Output "[Info]  AutomaticManagedPagefile: False (Default: True)" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\AutomaticManagedPagefile.txt"
                Write-Output "        Note: It seems that the automatic system page file management is disabled (for all drives)." | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\AutomaticManagedPagefile.txt" -Append
            }

            # DisablePagingExecutive - Specifies whether kernel-mode drivers and kernel-mode system code can be paged to disk when not in use (Default Value: 0).
            $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
            $DisablePagingExecutive = (Get-ItemProperty "HKLM:\System\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management" -Name DisablePagingExecutive).DisablePagingExecutive

            if ($DisablePagingExecutive -eq "0")
            {
                Write-Output "[Info]  DisablePagingExecutive: 0 (Default Value: 0)" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\DisablePagingExecutive.txt"
                Write-Output "        Note: Drivers and system code can be paged to disk as needed." | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\DisablePagingExecutive.txt" -Append
            }

            if ($DisablePagingExecutive -eq "1")
            {
                Write-Output "[Info]  DisablePagingExecutive: 1 (Default Value: 0)" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\DisablePagingExecutive.txt"
                Write-Output "        Note: Drivers and system code must remain in physical memory." | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\DisablePagingExecutive.txt" -Append
            }

            # NTFS Pagefile Encryption --> Encrypting File System (EFS) 
            $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
            $NtfsEncryptPagingFile = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\FileSystem" -Name NtfsEncryptPagingFile).NtfsEncryptPagingFile

            switch($NtfsEncryptPagingFile) 
            {
                "0" { $PagefileEncryption = "Disabled" }
                "1" { $PagefileEncryption = "Enabled" }
            }

            Write-Output "[Info]  NTFS Pagefile Encryption: $PagefileEncryption" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\NtfsEncryptPagingFile.txt"

            # ExistingPageFiles (REG_MULTI_SZ)
            $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
            (Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management" -Name ExistingPageFiles).ExistingPageFiles | ForEach-Object{($_ -replace "^\\\?\?\\","")} | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\ExistingPageFiles.txt"

            # PagingFiles (REG_MULTI_SZ)
            $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
            (Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management" -Name PagingFiles).PagingFiles | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\PagingFiles.txt"

            # PagefileOnOsVolume
            $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
            
            if (Test-RegistryValue -Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management" -Value "PagefileOnOsVolume")
            {
                $PagefileOnOsVolume = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management" -Name PagefileOnOsVolume).PagefileOnOsVolume
                Write-Output "$PagefileOnOsVolume" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\PagefileOnOsVolume.txt"
            }

            # ClearPageFileAtShutdown - Specifies whether inactive pages in the paging file are filled with zeros when the system stops (Default Value: 0).
            $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
            $ClearPageFileAtShutdown = (Get-ItemProperty "HKLM:\System\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management" -Name ClearPageFileAtShutdown).ClearPageFileAtShutdown

            if ($ClearPageFileAtShutdown -eq "0")
            {
                Write-Output "[Info]  ClearPageFileAtShutdown: 0 (Default Value: 0)" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\ClearPageFileAtShutdown.txt"
                Write-Output "        Note: Inactive pages are not filled with zeros." | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\ClearPageFileAtShutdown.txt" -Append
            }

            if ($ClearPageFileAtShutdown -eq "1")
            {
                Write-Output "[Info]  ClearPageFileAtShutdown: 1 (Default Value: 0)" | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\ClearPageFileAtShutdown.txt"
                Write-Output "        Note: Inactive pages are filled with zeros." | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\ClearPageFileAtShutdown.txt" -Append
            }

            # Check if it is an Array --> Multiple Pagefiles
            $PageFileList = Get-WmiObject -Class Win32_PageFile

            if ($PageFileList -is [array])
            {
                # Count Pagefiles
                # Note: Windows supports up to 16 paging files; however, normally only one is used.
                $Count = $PageFileList.Length
                if ($Count -gt 0)
                {
                    Write-Output "[Info]  $Count Page File(s) found"
                    Write-Output "[Info]  $Count Page File(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
                else
                {
                    Write-Output "[Info]  No Page File found"
                }

                $i = 1

                foreach ($PageFile in $PageFileList)
                {
                    # Name
                    $Name = ($PageFile | Select-Object -Property Name).Name

                    # File Size
                    $Bytes = ($PageFile | Select-Object -Property FileSize).FileSize
                    $FileSize = Get-FileSize($Bytes)

                    Write-Output "[Info]  Pagefile #$i`: $Name [$FileSize]"
                    Write-Output "[Info]  Pagefile #$i`: $Name [$FileSize]" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    $i += 1
                }
            }
            else
            {
                # Name
                $Name = (Get-WmiObject -Class Win32_PageFileUsage | Select-Object -Property Name).Name
                Write-Output "[Info]  Pagefile Name: $Name"
                Write-Output "[Info]  PageFile Name: $Name" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                # File Size
                $AllocatedBaseSize = (Get-WmiObject -Class Win32_PageFileUsage | Select-Object -Property AllocatedBaseSize).AllocatedBaseSize
                $Length = ($AllocatedBaseSize*1024*1024)
                $FileSize = Get-FileSize($Length)
                Write-Output "[Info]  Pagefile Size: $FileSize"
                Write-Output "[Info]  Pagefile Size: $FileSize" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Collecting Pagefile(s)

            # .NET 4.0 Framework
            if (Test-Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")
            {
                Write-Output "[Info]  Collecting Pagefile(s) [approx. 1-20 min] ..."
                Write-Output "[Info]  Collecting Pagefile(s) [approx. 1-20 min] ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                $StartTime_MagnetRESPONSE = (Get-Date)
                & $MagnetRESPONSE /accepteula /nodiagnosticdata /unattended /caseref:"Collect-MemoryDump-v1.1.0" /output:"$OUTPUT_FOLDER\Memory\Pagefile" /capturepagefile /capturevolatile /captureextendedprocessinfo /saveprocfiles
                Wait-Process -Name "MagnetRESPONSE"
                Start-Sleep -Seconds 1
                $EndTime_MagnetRESPONSE = (Get-Date)
                $Time_MagnetRESPONSE = ($EndTime_MagnetRESPONSE-$StartTime_MagnetRESPONSE)
                ('Pagefile Collection duration: {0} h {1} min {2} sec' -f $Time_MagnetRESPONSE.Hours, $Time_MagnetRESPONSE.Minutes, $Time_MagnetRESPONSE.Seconds) >> "$OUTPUT_FOLDER\Memory\Pagefile\Stats.txt"

                # Rename Archive
                if (Test-Path "$OUTPUT_FOLDER\Memory\Pagefile\*\*.zip")
                {
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Pagefile\*\*.zip" | Rename-Item -NewName {"$env:COMPUTERNAME.zip"}
                }

                # Rename Directory
                if (Test-Path "$OUTPUT_FOLDER\Memory\Pagefile\*\*.zip")
                {
                    Get-ChildItem "$OUTPUT_FOLDER\Memory\Pagefile" | Where-Object {($_.FullName -match "MagnetRESPONSE")} | Rename-Item -NewName {"Pagefile"}
                }

                # MD5 Calculation
                if (Test-Path "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip") 
                {
                    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue)
                    {
                        Write-Output "[Info]  Calculating MD5 checksum of $env:COMPUTERNAME.zip [approx. 1-2 min] ..."
                        Write-Output "[Info]  Calculating MD5 checksum of $env:COMPUTERNAME.zip [approx. 1-2 min] ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $StartTime_MD5 = (Get-Date)
                        $MD5 = (Get-FileHash -LiteralPath "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip" -Algorithm MD5).Hash
                        Write-Output "[Info]  MD5 Hash: $MD5"
                        Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $MD5 > "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\MD5.txt"
                        $EndTime_MD5 = (Get-Date)
                        $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                        ('MD5 Calculation duration:     {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\Pagefile\Stats.txt"
                    }
                }

                # Get File Size of "$env:COMPUTERNAME.zip"
                if (Test-Path "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip") 
                {
                    $Length = $Length = (Get-Item -Path "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip").Length
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Archive Size: $Size"
                    Write-Output "[Info]  Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }

                # Create Time (ISO 8601)
                if (Test-Path "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip") 
                {
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }

                # Last Modified Time (ISO 8601)
                if (Test-Path "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip") 
                {
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\Pagefile\Pagefile\$env:COMPUTERNAME.zip").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }
            else
            {
                Write-Output "[Error] NET Framework v4 NOT found. Pagefile Collection will be skipped ..."
                Write-Output "[Error] NET Framework v4 NOT found. Pagefile Collection will be skipped ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # WMI Classes

            # Win32_PageFileUsage
            $PageFileList = Get-WmiObject -Class Win32_PageFile

            if ($PageFileList -is [array])
            {
                $PageFileList = Get-WmiObject -Class Win32_PageFileUsage

                $i = 1

                foreach ($PageFile in $PageFileList)
                {
                    $Name              = ($PageFile | Select-Object -Property Name).Name
                    $InstallDateString = ($PageFile | Select-Object InstallDate).InstallDate
                    $InstallDate       = ([Management.ManagementDateTimeConverter]::ToDateTime("$InstallDateString")).ToUniversalTime()
                    $AllocatedBaseSize = ($PageFile | Select-Object -Property AllocatedBaseSize).AllocatedBaseSize
                    $CurrentUsage      = ($PageFile | Select-Object -Property CurrentUsage).CurrentUsage
                    $PeakUsage         = ($PageFile | Select-Object -Property PeakUsage).PeakUsage
                    $TempPageFile      = ($PageFile | Select-Object -Property TempPageFile).TempPageFile

                    $Win32_PageFileUsage  = [PSCustomObject]@{
                    "Pagefile #$i"        = $Name
                    "Install Date"        = ($InstallDate).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "Allocated Base Size" = "$AllocatedBaseSize MB"
                    "Current Usage"       = "$CurrentUsage MB"
                    "Peak Usage"          = "$PeakUsage MB"
                    "Temp Page File"      = $TempPageFile
                    }

                    ($Win32_PageFileUsage | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\Win32_PageFileUsage_Pagefile-$i.txt"

                $i += 1

                }
            }
            else
            {
                $PageFile          = Get-WmiObject -Class Win32_PageFileUsage
                $Name              = ($PageFile | Select-Object -Property Name).Name
                $InstallDateString = ($PageFile | Select-Object InstallDate).InstallDate
                $InstallDate       = ([Management.ManagementDateTimeConverter]::ToDateTime("$InstallDateString")).ToUniversalTime()
                $AllocatedBaseSize = ($PageFile | Select-Object -Property AllocatedBaseSize).AllocatedBaseSize
                $CurrentUsage      = ($PageFile | Select-Object -Property CurrentUsage).CurrentUsage
                $PeakUsage         = ($PageFile | Select-Object -Property PeakUsage).PeakUsage
                $TempPageFile      = ($PageFile | Select-Object -Property TempPageFile).TempPageFile

                $Win32_PageFileUsage  = [PSCustomObject]@{
                "Pagefile    "        = $Name
                "Install Date"        = ($InstallDate).ToString("yyyy-MM-dd HH:mm:ss UTC")
                "Allocated Base Size" = "$AllocatedBaseSize MB"
                "Current Usage"       = "$CurrentUsage MB"
                "Peak Usage"          = "$PeakUsage MB"
                "Temp Page File"      = $TempPageFile
                }

                ($Win32_PageFileUsage | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\Win32_PageFileUsage.txt"
            }

            # Win32_PageFileSetting
            [string]$AutoManaged = $null -eq (Get-WmiObject -Class Win32_PageFile)

            if ($AutoManaged -eq "False")
            {
                $PageFileList = Get-WmiObject -Class Win32_PageFileSetting

                if ($PageFileList -is [array])
                {
                    $i = 1

                    foreach ($PageFile in $PageFileList)
                    {
                        $Name        = $PageFile.Name
                        $InitialSize = $PageFile.InitialSize
                        $MaximumSize = $PageFile.MaximumSize

                        $Win32_PageFileSetting = [PSCustomObject]@{
                        "Pagefile #$i"         = $Name
                        "Initial Size"         = "$InitialSize MB"
                        "Maximum Size"         = "$MaximumSize MB"
                        }

                        ($Win32_PageFileSetting | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\Win32_PageFileSetting_Pagefile-$i.txt"

                    $i += 1

                    }
                }
                else
                {
                    $PageFile    = Get-WmiObject -Class Win32_PageFileSetting
                    $Name        = $PageFile.Name
                    $InitialSize = $PageFile.InitialSize
                    $MaximumSize = $PageFile.MaximumSize

                    $Win32_PageFileSetting = [PSCustomObject]@{
                    "Pagefile"             = $Name
                    "Initial Size"         = "$InitialSize MB"
                    "Maximum Size"         = "$MaximumSize MB"
                    }

                    ($Win32_PageFileSetting | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\Win32_PageFileSetting.txt"
                }
            }

            # Win32_PageFile
            [string]$AutoManaged = $null -eq (Get-WmiObject -Class Win32_PageFile)

            if ($AutoManaged -eq "False")
            {
                $PageFileList = Get-WmiObject -Class Win32_PageFile

                if ($PageFileList -is [array])
                {
                    $i = 1

                    foreach ($PageFile in $PageFileList)
                    {
                        $Name               = $PageFile.Name
                        $Compressed         = $PageFile.Compressed
                        $CompressionMethod  = $PageFile.CompressionMethod
                        $CreationDateString = ($PageFile | Select-Object CreationDate).CreationDate
                        $CreationDate       = ([Management.ManagementDateTimeConverter]::ToDateTime("$CreationDateString")).ToUniversalTime()
                        $Encrypted          = $PageFile.Encrypted
                        $EncryptionMethod   = $PageFile.EncryptionMethod
                        $FileSize           = $PageFile.FileSize
                        $InitialSize        = $PageFile.InitialSize
                        $InstallDateString  = $PageFile.InstallDate
                        $InstallDate        = ([Management.ManagementDateTimeConverter]::ToDateTime("$InstallDateString")).ToUniversalTime()
                        $LastAccessedString = $PageFile.LastAccessed
                        $LastAccessed       = ([Management.ManagementDateTimeConverter]::ToDateTime("$LastAccessedString")).ToUniversalTime()
                        $LastModifiedString = $PageFile.LastModified
                        $LastModified       = ([Management.ManagementDateTimeConverter]::ToDateTime("$LastModifiedString")).ToUniversalTime()
                        $MaximumSize        = $PageFile.MaximumSize

                        $Win32_PageFile     = [PSCustomObject]@{
                        "Pagefile"          = $Name
                        "Compressed"        = $Compressed
                        "CompressionMethod" = $CompressionMethod
                        "CreationDate"      = ($CreationDate).ToString("yyyy-MM-dd HH:mm:ss UTC")
                        "Encrypted"         = $Encrypted
                        "EncryptionMethod"  = $EncryptionMethod
                        "FileSize"          = $FileSize
                        "Initial Size"      = "$InitialSize MB"
                        "InstallDate"       = ($InstallDate).ToString("yyyy-MM-dd HH:mm:ss UTC")
                        "LastAccessed"      = ($LastAccessed).ToString("yyyy-MM-dd HH:mm:ss UTC")
                        "LastModified"      = ($LastModified).ToString("yyyy-MM-dd HH:mm:ss UTC")
                        "MaximumSize"       = "$MaximumSize MB"
                        }

                        ($Win32_PageFile | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\Win32_PageFile_Pagefile-$i.txt"

                        $i += 1

                    }
                }
                else
                {
                    $PageFile           = Get-WmiObject -Class Win32_Pagefile
                    $Name               = $PageFile.Name
                    $Compressed         = $PageFile.Compressed
                    $CompressionMethod  = $PageFile.CompressionMethod
                    $CreationDateString = ($PageFile | Select-Object CreationDate).CreationDate
                    $CreationDate       = ([Management.ManagementDateTimeConverter]::ToDateTime("$CreationDateString")).ToUniversalTime()
                    $Encrypted          = $PageFile.Encrypted
                    $EncryptionMethod   = $PageFile.EncryptionMethod
                    $FileSize           = $PageFile.FileSize
                    $InitialSize        = $PageFile.InitialSize
                    $InstallDateString  = $PageFile.InstallDate
                    $InstallDate        = ([Management.ManagementDateTimeConverter]::ToDateTime("$InstallDateString")).ToUniversalTime()
                    $LastAccessedString = $PageFile.LastAccessed
                    $LastAccessed       = ([Management.ManagementDateTimeConverter]::ToDateTime("$LastAccessedString")).ToUniversalTime()
                    $LastModifiedString = $PageFile.LastModified
                    $LastModified       = ([Management.ManagementDateTimeConverter]::ToDateTime("$LastModifiedString")).ToUniversalTime()
                    $MaximumSize        = $PageFile.MaximumSize

                    $Win32_PageFile     = [PSCustomObject]@{
                    "Pagefile"          = $Name
                    "Compressed"        = $Compressed
                    "CompressionMethod" = $CompressionMethod
                    "CreationDate"      = ($CreationDate).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "Encrypted"         = $Encrypted
                    "EncryptionMethod"  = $EncryptionMethod
                    "FileSize"          = $FileSize
                    "Initial Size"      = "$InitialSize MB"
                    "InstallDate"       = ($InstallDate).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "LastAccessed"      = ($LastAccessed).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "LastModified"      = ($LastModified).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "MaximumSize"       = "$MaximumSize MB"
                    }

                    ($Win32_PageFile | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\Memory\Pagefile\PageFileInfo\Win32_PageFile.txt"
                } 
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        Write-Output "[Error] MagnetRESPONSE.exe NOT found."
        Write-Output "[Error] MagnetRESPONSE.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

#endregion Pagefile

#############################################################################################################################################################################################

#region Triage

# Collects the following files/locations:# - Amcache data# - AnyDesk Logs
# - Chrome Browser History
# - Edge Browser History# - Firefox Browser History
# - Firewall Logs# - Jumplist files
# - LogMeIn Logs
# - Master File Table ($MFT)# - NTUSER.DAT files
# - PowerShell history
# - Prefetch files# - Program Compatibility Assistant files# - Recent Link files
# - Recycle Bin
# - Registry Hives# - Scheduled Tasks
# - SRUM data
# - TeamViewer Logs
# - UsrClass.dat files
# - Windows Event Logs
# - Windows Timeline data

Function Get-Triage
{
    # Magnet RESPONSE
    if (Test-Path "$MagnetRESPONSE") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$MagnetRESPONSE" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        if ($MD5 -eq "2A3BA98713A243F90CD0582C64F13CFB")
        {
            # Triage
            New-Item "$OUTPUT_FOLDER\Triage" -ItemType Directory -Force | Out-Null

            # Collecting Artifacts

            # .NET 4.0 Framework
            if (Test-Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")
            {
                Write-Output "[Info]  Collecting Forensic Artifacts [approx. 1-15 min] ... "
                Write-Output "[Info]  Collecting Forensic Artifacts [approx. 1-15 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                $StartTime_Triage = (Get-Date)
                & $MagnetRESPONSE /accepteula /nodiagnosticdata /unattended /caseref:"Collect-MemoryDump-v1.1.0" /output:"$OUTPUT_FOLDER\Triage" /capturesystemfiles /saveprocfiles
                Wait-Process -Name "MagnetRESPONSE"
                Start-Sleep -Seconds 1
                $EndTime_Triage = (Get-Date)
                $Time_Triage = ($EndTime_Triage-$StartTime_Triage)
                ('Triage Collection duration: {0} h {1} min {2} sec' -f $Time_Triage.Hours, $Time_Triage.Minutes, $Time_Triage.Seconds) >> "$OUTPUT_FOLDER\Triage\Stats.txt"

                # Rename Archive
                if (Test-Path "$OUTPUT_FOLDER\Triage\*\*.zip")
                {
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Triage\*\*.zip" | Rename-Item -NewName {"$env:COMPUTERNAME.zip"}
                }

                # Rename Directory
                if (Test-Path "$OUTPUT_FOLDER\Triage\*\*.zip")
                {
                    Get-ChildItem "$OUTPUT_FOLDER\Triage" | Where-Object {($_.FullName -match "MagnetRESPONSE")} | Rename-Item -NewName {"Artifacts"}
                }

                # MD5 Calculation
                if (Test-Path "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip") 
                {
                    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue)
                    {
                        Write-Output "[Info]  Calculating MD5 checksum of $env:COMPUTERNAME.zip [approx. 1-2 min] ... "
                        Write-Output "[Info]  Calculating MD5 checksum of $env:COMPUTERNAME.zip [approx. 1-2 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $StartTime_MD5 = (Get-Date)
                        $MD5 = (Get-FileHash -LiteralPath "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip" -Algorithm MD5).Hash
                        Write-Output "[Info]  MD5 Hash: $MD5"
                        Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $MD5 > "$OUTPUT_FOLDER\Triage\Artifacts\MD5.txt"
                        $EndTime_MD5 = (Get-Date)
                        $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                        ('MD5 Calculation duration:   {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Triage\Stats.txt"
                    }
                }

                # Get File Size of "$env:COMPUTERNAME.zip"
                if (Test-Path "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip") 
                {
                    $Length = $Length = (Get-Item -Path "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip").Length
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Archive Size: $Size"
                    Write-Output "[Info]  Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }

                # Create Time (ISO 8601)
                if (Test-Path "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip") 
                {
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }

                # Last Modified Time (ISO 8601)
                if (Test-Path "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip") 
                {
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Triage\Artifacts\$env:COMPUTERNAME.zip").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }
            else
            {
                Write-Output "[Error] NET Framework v4 NOT found. Triage Collection will be skipped ..."
                Write-Output "[Error] NET Framework v4 NOT found. Triage Collection will be skipped ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        Write-Output "[Error] MagnetRESPONSE.exe NOT found."
        Write-Output "[Error] MagnetRESPONSE.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

#endregion Triage

#############################################################################################################################################################################################

#region Comae

Function New-ComaeSnapshot
{
    # DumpIt
    if (Test-Path "$DumpIt") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$DumpIt" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        # ARM64 or x64 or x86
        if (($MD5 -eq "4B39D63B86FFE39BBAE0415C400003C7") -Or ($MD5 -eq "0F10DA3A5EB49D17D73D8E195FE32F85") -OR ($MD5 -eq "586C57AD0EEA179FCAE4B8BA117F2AB9"))
        {
            # Get Physical Memory Size
            if ($PSVersionTable.PSVersion.Major -ge 3)
            {
                $TotalMemory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                $TotalMemory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Check Available Space (GB)
            $DriveLetter = "$SCRIPT_DIR".Substring(0,2)
            $AvailableSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "deviceid='$DriveLetter'" | Select-Object FreeSpace).FreeSpace | ForEach-Object {"{0}" -f ([math]::round(($_ / 1GB)))}
            
            [int]$TotalMemoryInt32 = [convert]::ToInt32($TotalMemory, 10)
            [int]$AvailableSpaceInt32 = [convert]::ToInt32($AvailableSpace, 10)
            [int]$AdditionalSpaceInt32 = ($TotalMemoryInt32/100*12.5) # +12,5%
            [int]$RequiredSpaceInt32 = ([int]$TotalMemoryInt32)+([int]$AdditionalSpaceInt32)

            if ($RequiredSpaceInt32 -gt $AvailableSpaceInt32)
            {
                Write-Output "[Error] Not enough disk space to save memory dump file."
                Write-Output "[Error] Not enough disk space to save memory dump file." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                Write-Output ""
                $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
                Exit
            }

            # Check if output directory exists
            if (Test-Path $OUTPUT_FOLDER\Memory\DumpIt)
            {
                # Check for output directory content
                if (Test-Path $OUTPUT_FOLDER\Memory\DumpIt\*)
                {
                    # Delete output directory content after confirmation
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\DumpIt" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -Confirm
                }
            }
            else 
            {
                # Creating Output Directory
                New-Item "$OUTPUT_FOLDER\Memory\DumpIt" -ItemType Directory -Force | Out-Null
            }

            # Microsoft Crash Dump
            $StartTime_MemoryAcquisition = (Get-Date)
            Write-Output "[Info]  Creating Memory Snapshot w/ DumpIt (Microsoft Crash Dump) [approx. 1-5 min] ... "
            Write-Output "[Info]  Creating Memory Snapshot w/ DumpIt (Microsoft Crash Dump) [approx. 1-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            & $DumpIt /T DMP /N /Q /NOCOMPRESS /O "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.dmp" 2>&1 | Out-File "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log"
            $EndTime_MemoryAcquisition = (Get-Date)
            $Time_MemoryAcquisition = ($EndTime_MemoryAcquisition-$StartTime_MemoryAcquisition)
            ('Memory Acquisition duration: {0} h {1} min {2} sec' -f $Time_MemoryAcquisition.Hours, $Time_MemoryAcquisition.Minutes, $Time_MemoryAcquisition.Seconds) >> "$OUTPUT_FOLDER\Memory\DumpIt\Stats.txt"

            # Error: Can't install the driver
            if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log")
            {
                if (Get-Content "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" | Select-String -Pattern "Error: Can't install the driver." -Quiet)
                {
                    Write-Output "[Error] Installing the DumpIt.sys driver failed. Please try WinPMEM."
                    Write-Output "[Error] Installing the DumpIt.sys driver failed. Please try WinPMEM." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }

            # SHA256
            if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log")
            {
                $SHA256 = Get-Content "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" | Select-String -Pattern "[A-Fa-f0-9]{64}" | ForEach-Object { $PSItem.Matches[0].Value } | Select-Object -First 1
                if ($SHA256)
                {
                    Write-Output "[Info]  SHA256 Hash: $SHA256"
                    Write-Output "[Info]  SHA256 Hash: $SHA256" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }

            # Processing... Failed.
            if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log")
            {
                # Error: The request could not be performed because of an I/O device error.
                if (Get-Content "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" | Select-String -Pattern "Error: The request could not be performed because of an I/O device error." -Quiet)
                {
                    Write-Output "[Error] The request could not be performed because of an I/O device error."
                }
            }

            # Collecting PageFile
            if ($PageFile -eq "--PageFile")
            {
                Get-Pagefile
            }
            
            # Creating Secure Archive File
            if (Test-Path "$7za") 
            {
                if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.dmp") 
                {
                    $StartTime_Archive = (Get-Date)
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... "
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.7z" "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.dmp" "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" > $null 2>&1
                    $EndTime_Archive = (Get-Date)
                    $Time_Archive = ($EndTime_Archive-$StartTime_Archive)
                    ('Archive Creation duration:   {0} h {1} min {2} sec' -f $Time_Archive.Hours, $Time_Archive.Minutes, $Time_Archive.Seconds) >> "$OUTPUT_FOLDER\Memory\DumpIt\Stats.txt"

                    # Remove all files except "$env:COMPUTERNAME.7z" and "Stats.txt"
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\DumpIt" -Exclude "$env:COMPUTERNAME.7z*", "Stats.txt" -Recurse -Force | ForEach-Object ($_) {Remove-Item $_.FullName}

                    # Get File Size of "$env:COMPUTERNAME.7z"
                    $Length = (Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\DumpIt" | Measure-Object -Property Length -Sum).Sum
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Total Archive Size: $Size"
                    Write-Output "[Info]  Total Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Create Time (ISO 8601)
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.7z").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Last Modified Time (ISO 8601)
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.7z").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }
            else
            {
                Write-Output "[Error] 7za.exe NOT found."
                Write-Output "[Error] 7za.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        Write-Output "[Error] DumpIt.exe NOT found."
        Write-Output "[Error] DumpIt.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

# DumpIt
if ($Tool -eq "-Comae")
{
    New-ComaeSnapshot
}

#endregion Comae

#############################################################################################################################################################################################

#region DumpIt

Function New-DumpItSnapshot
{
    # DumpIt
    if (Test-Path "$DumpIt") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$DumpIt" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        # ARM64 or x64 or x86
        if (($MD5 -eq "4B39D63B86FFE39BBAE0415C400003C7") -Or ($MD5 -eq "0F10DA3A5EB49D17D73D8E195FE32F85") -OR ($MD5 -eq "586C57AD0EEA179FCAE4B8BA117F2AB9"))
        {
            # Get Physical Memory Size
            if ($PSVersionTable.PSVersion.Major -ge 3)
            {
                $TotalMemory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                $TotalMemory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Check Available Space (GB)
            $DriveLetter = "$SCRIPT_DIR".Substring(0,2)
            $AvailableSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "deviceid='$DriveLetter'" | Select-Object FreeSpace).FreeSpace | ForEach-Object {"{0}" -f ([math]::round(($_ / 1GB)))}
            
            [int]$TotalMemoryInt32 = [convert]::ToInt32($TotalMemory, 10)
            [int]$AvailableSpaceInt32 = [convert]::ToInt32($AvailableSpace, 10)
            [int]$AdditionalSpaceInt32 = ($TotalMemoryInt32/100*12.5) # +12,5%
            [int]$RequiredSpaceInt32 = ([int]$TotalMemoryInt32)+([int]$AdditionalSpaceInt32)

            if ($RequiredSpaceInt32 -gt $AvailableSpaceInt32)
            {
                Write-Output "[Error] Not enough disk space to save memory dump file."
                Write-Output "[Error] Not enough disk space to save memory dump file." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                Write-Output ""
                $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
                Exit
            }

            # Check if output directory exists
            if (Test-Path $OUTPUT_FOLDER\Memory\DumpIt)
            {
                # Check for output directory content
                if (Test-Path $OUTPUT_FOLDER\Memory\DumpIt\*)
                {
                    # Delete output directory content after confirmation
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\DumpIt" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -Confirm
                }
            }
            else 
            {
                # Creating Output Directory
                New-Item "$OUTPUT_FOLDER\Memory\DumpIt" -ItemType Directory -Force | Out-Null
            }

            # Raw Physical Memory Dump
            # Note: DumpIt uses automatically .bin file extension.
            $StartTime_MemoryAcquisition = (Get-Date)
            Write-Output "[Info]  Creating Memory Snapshot w/ DumpIt (Raw Physical Memory Dump) [approx. 1-5 min] ... "
            Write-Output "[Info]  Creating Memory Snapshot w/ DumpIt (Raw Physical Memory Dump) [approx. 1-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            & $DumpIt /T RAW /N /Q /U /O "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.bin" 2>&1 | Out-File "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log"
            $EndTime_MemoryAcquisition = (Get-Date)
            $Time_MemoryAcquisition = ($EndTime_MemoryAcquisition-$StartTime_MemoryAcquisition)
            ('Memory Acquisition duration: {0} h {1} min {2} sec' -f $Time_MemoryAcquisition.Hours, $Time_MemoryAcquisition.Minutes, $Time_MemoryAcquisition.Seconds) >> "$OUTPUT_FOLDER\Memory\DumpIt\Stats.txt"

            # Error: Can't install the driver
            if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log")
            {
                if (Get-Content "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" | Select-String -Pattern "Error: Can't install the driver." -Quiet)
                {
                    Write-Output "[Error] Installing the DumpIt.sys driver failed. Please try WinPMEM."
                    Write-Output "[Error] Installing the DumpIt.sys driver failed. Please try WinPMEM." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }

            # SHA256
            if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log")
            {
                $SHA256 = Get-Content "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" | Select-String -Pattern "[A-Fa-f0-9]{64}" | ForEach-Object { $PSItem.Matches[0].Value } | Select-Object -First 1
                if ($SHA256)
                {
                    Write-Output "[Info]  SHA256 Hash: $SHA256"
                    Write-Output "[Info]  SHA256 Hash: $SHA256" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }

            # Collecting PageFile
            if ($PageFile -eq "--PageFile")
            {
                Get-Pagefile
            }
            
            # Creating Secure Archive File
            if (Test-Path "$7za") 
            {
                if (Test-Path "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.bin") 
                {
                    $StartTime_Archive = (Get-Date)
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... "
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.7z" "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.bin" "$OUTPUT_FOLDER\Memory\DumpIt\DumpIt.log" > $null 2>&1
                    $EndTime_Archive = (Get-Date)
                    $Time_Archive = ($EndTime_Archive-$StartTime_Archive)
                    ('Archive Creation duration:   {0} h {1} min {2} sec' -f $Time_Archive.Hours, $Time_Archive.Minutes, $Time_Archive.Seconds) >> "$OUTPUT_FOLDER\Memory\DumpIt\Stats.txt"

                    # Remove all files except "$env:COMPUTERNAME.7z" and "Stats.txt"
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\DumpIt" -Exclude "$env:COMPUTERNAME.7z*", "Stats.txt" -Recurse -Force | ForEach-Object ($_) {Remove-Item $_.FullName}

                    # Get File Size of "$env:COMPUTERNAME.7z"
                    $Length = (Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\DumpIt" | Measure-Object -Property Length -Sum).Sum
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Total Archive Size: $Size"
                    Write-Output "[Info]  Total Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Create Time (ISO 8601)
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.7z").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Last Modified Time (ISO 8601)
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\DumpIt\$env:COMPUTERNAME.7z").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # TODO
                }
            }
            else
            {
                Write-Output "[Error] 7za.exe NOT found."
                Write-Output "[Error] 7za.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Triage Collection
            if ($Triage -eq "--Triage")
            {
                Get-Triage
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        Write-Output "[Error] DumpIt.exe NOT found."
        Write-Output "[Error] DumpIt.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

# DumpIt
if ($Tool -eq "-DumpIt")
{
    New-DumpItSnapshot
}

#endregion DumpIt

#############################################################################################################################################################################################

#region RamCapture

Function New-RamCapture
{
    # ARM64 Support
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
    {
        Write-Output "[Error] ARM64 architecture is NOT supported by Magnet RAM Capture."
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # Magnet RAM Capture
    if (Test-Path "$MRC") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$MRC" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        if ($MD5 -eq "51D286BDF58359417A28E3132ABA957F")
        {
            # Get Physical Memory Size
            if ($PSVersionTable.PSVersion.Major -ge 3)
            {
                $TotalMemory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                $TotalMemory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Check Available Space (GB)
            $DriveLetter = "$SCRIPT_DIR".Substring(0,2)
            $AvailableSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "deviceid='$DriveLetter'" | Select-Object FreeSpace).FreeSpace | ForEach-Object {"{0}" -f ([math]::round(($_ / 1GB)))}
            
            [int]$TotalMemoryInt32 = [convert]::ToInt32($TotalMemory, 10)
            [int]$AvailableSpaceInt32 = [convert]::ToInt32($AvailableSpace, 10)
            [int]$AdditionalSpaceInt32 = ($TotalMemoryInt32/100*12.5) # +12,5%
            [int]$RequiredSpaceInt32 = ([int]$TotalMemoryInt32)+([int]$AdditionalSpaceInt32)

            if ($RequiredSpaceInt32 -gt $AvailableSpaceInt32)
            {
                Write-Output "[Error] Not enough disk space to save memory dump file."
                Write-Output "[Error] Not enough disk space to save memory dump file." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                Write-Output ""
                $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
                Exit
            }

            # Check if output directory exists
            if (Test-Path $OUTPUT_FOLDER\Memory\Magnet)
            {
                # Check for output directory content
                if (Test-Path $OUTPUT_FOLDER\Memory\Magnet\*)
                {
                    # Delete output directory content after confirmation
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Magnet" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -Confirm
                }
            }
            else 
            {
                # Creating Output Directory
                New-Item "$OUTPUT_FOLDER\Memory\Magnet" -ItemType Directory -Force | Out-Null
            }

            # Raw Physical Memory Dump 
            $StartTime_MemoryAcquisition = (Get-Date)
            Write-Output "[Info]  Creating Memory Snapshot w/ Magnet RAM Capture (Raw Physical Memory Dump) [approx. 5-10 min] ... "
            Write-Output "[Info]  Creating Memory Snapshot w/ Magnet RAM Capture (Raw Physical Memory Dump) [approx. 5-10 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            & $MRC /accepteula /go "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.raw"
            Wait-Process -Name "MRCv120"
            Start-Sleep -Seconds 1
            $EndTime_MemoryAcquisition = (Get-Date)
            $Time_MemoryAcquisition = ($EndTime_MemoryAcquisition-$StartTime_MemoryAcquisition)
            ('Memory Acquisition duration: {0} h {1} min {2} sec' -f $Time_MemoryAcquisition.Hours, $Time_MemoryAcquisition.Minutes, $Time_MemoryAcquisition.Seconds) >> "$OUTPUT_FOLDER\Memory\Magnet\Stats.txt"

            # Collecting PageFile
            if ($PageFile -eq "--PageFile")
            {
                Get-Pagefile
            }

            # MD5 Calculation
            if (Test-Path "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.raw") 
            {
                if (Get-Command Get-FileHash -ErrorAction SilentlyContinue)
                {
                    Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... "
                    Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    $StartTime_MD5 = (Get-Date)
                    $MD5 = (Get-FileHash -LiteralPath "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.raw" -Algorithm MD5).Hash
                    Write-Output "[Info]  MD5 Hash: $MD5"
                    Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    $MD5 > "$OUTPUT_FOLDER\Memory\Magnet\MD5.txt"
                    $EndTime_MD5 = (Get-Date)
                    $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                    ('MD5 Calculation duration:    {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\Magnet\Stats.txt"
                }
                else
                {
                    if (Test-Path "$env:SystemDrive\Windows\System32\certutil.exe")
                    {
                        Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... "
                        Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $StartTime_MD5 = (Get-Date)
                        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
                        $MD5 = ((& $certUtil -hashfile "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.raw" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()
                        Write-Output "[Info]  MD5 Hash: $MD5"
                        Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $MD5 > "$OUTPUT_FOLDER\Memory\Magnet\MD5.txt"
                        $EndTime_MD5 = (Get-Date)
                        $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                        ('MD5 Calculation duration:    {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\Magnet\Stats.txt"
                    }
                }
            }

            # Creating Secure Archive File
            if (Test-Path "$7za") 
            {
                if (Test-Path "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.raw") 
                {
                    $StartTime_Archive = (Get-Date)
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... "
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.7z" "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.raw" "$OUTPUT_FOLDER\Memory\Magnet\MD5.txt" > $null 2>&1
                    $EndTime_Archive = (Get-Date)
                    $Time_Archive = ($EndTime_Archive-$StartTime_Archive)
                    ('Archive Creation duration:   {0} h {1} min {2} sec' -f $Time_Archive.Hours, $Time_Archive.Minutes, $Time_Archive.Seconds) >> "$OUTPUT_FOLDER\Memory\Magnet\Stats.txt"

                    # Remove all files except "$env:COMPUTERNAME.7z"
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Magnet" -Exclude "$env:COMPUTERNAME.7z*", "Stats.txt" -Recurse -Force | ForEach-Object ($_) {Remove-Item $_.FullName}

                    # Get File Size of "$env:COMPUTERNAME.7z"
                    $Length = (Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Magnet" | Measure-Object -Property Length -Sum).Sum
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Total Archive Size: $Size"
                    Write-Output "[Info]  Total Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Create Time (ISO 8601)
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.7z").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Last Modified Time (ISO 8601)
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\Magnet\$env:COMPUTERNAME.7z").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }
            else
            {
                Write-Output "[Error] 7za.exe NOT found."
                Write-Output "[Error] 7za.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        Write-Output "[Error] MRCv120.exe NOT found."
        Write-Output "[Error] MRCv120.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

# Magnet RAM Capture
if ($Tool -eq "-RamCapture")
{
    New-RamCapture
}

#endregion RamCapture

#############################################################################################################################################################################################

#region WinPMEM

Function New-WinPMEMSnapshot
{
    # ARM64 Support
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
    {
        Write-Output "[Error] ARM64 architecture is NOT supported by WinPMEM."
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # WinPMEM
    if (Test-Path "$WinPMEM") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$WinPMEM" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        # x64 or x86
        if (($MD5 -eq "9DD3160679832165738BFABD7279ACEB") -Or ($MD5 -eq "C2BC7851F966BC39068345FB24BC8740"))
        {
            # Get Physical Memory Size
            if ($PSVersionTable.PSVersion.Major -ge 3)
            {
                $TotalMemory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                $TotalMemory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Check Available Space (GB)
            $DriveLetter = "$SCRIPT_DIR".Substring(0,2)
            $AvailableSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "deviceid='$DriveLetter'" | Select-Object FreeSpace).FreeSpace | ForEach-Object {"{0}" -f ([math]::round(($_ / 1GB)))}
            
            [int]$TotalMemoryInt32 = [convert]::ToInt32($TotalMemory, 10)
            [int]$AvailableSpaceInt32 = [convert]::ToInt32($AvailableSpace, 10)
            [int]$AdditionalSpaceInt32 = ($TotalMemoryInt32/100*12.5) # +12,5%
            [int]$RequiredSpaceInt32 = ([int]$TotalMemoryInt32)+([int]$AdditionalSpaceInt32)

            if ($RequiredSpaceInt32 -gt $AvailableSpaceInt32)
            {
                Write-Output "[Error] Not enough disk space to save memory dump file."
                Write-Output "[Error] Not enough disk space to save memory dump file." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                Write-Output ""
                $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
                Exit
            }

            # Check if output directory exists
            if (Test-Path $OUTPUT_FOLDER\Memory\WinPMEM)
            {
                # Check for output directory content
                if (Test-Path $OUTPUT_FOLDER\Memory\WinPMEM\*)
                {
                    # Delete output directory content after confirmation
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\WinPMEM" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -Confirm
                }
            }
            else 
            {
                # Creating Output Directory
                New-Item "$OUTPUT_FOLDER\Memory\WinPMEM" -ItemType Directory -Force | Out-Null
            }

            # Raw Physical Memory Dump
            $StartTime_MemoryAcquisition = (Get-Date)
            Write-Output "[Info]  Creating Memory Snapshot w/ WinPMEM (Raw Physical Memory Dump) [approx. 1-6 min] ... "
            Write-Output "[Info]  Creating Memory Snapshot w/ WinPMEM (Raw Physical Memory Dump) [approx. 1-6 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            & $WinPMEM "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.raw" > "$OUTPUT_FOLDER\Memory\WinPMEM\stdout.txt" 2> "$OUTPUT_FOLDER\Memory\WinPMEM\stderr.txt"
            $EndTime_MemoryAcquisition = (Get-Date)
            $Time_MemoryAcquisition = ($EndTime_MemoryAcquisition-$StartTime_MemoryAcquisition)
            ('Memory Acquisition duration: {0} h {1} min {2} sec' -f $Time_MemoryAcquisition.Hours, $Time_MemoryAcquisition.Minutes, $Time_MemoryAcquisition.Seconds) >> "$OUTPUT_FOLDER\Memory\WinPMEM\Stats.txt"

            # Collecting PageFile
            if ($PageFile -eq "--PageFile")
            {
                Get-Pagefile
            }

            # MD5 Calculation
            if (Test-Path "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.raw") 
            {
                if (Get-Command Get-FileHash -ErrorAction SilentlyContinue)
                {
                    Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... "
                    Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    $StartTime_MD5 = (Get-Date)
                    $MD5 = (Get-FileHash -LiteralPath "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.raw" -Algorithm MD5).Hash
                    Write-Output "[Info]  MD5 Hash: $MD5"
                    Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    $MD5 > "$OUTPUT_FOLDER\Memory\WinPMEM\MD5.txt"
                    $EndTime_MD5 = (Get-Date)
                    $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                    ('MD5 Calculation duration:    {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\WinPMEM\Stats.txt"
                }
                else
                {
                    if (Test-Path "$env:SystemDrive\Windows\System32\certutil.exe")
                    {
                        Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... "
                        Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $StartTime_MD5 = (Get-Date)
                        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
                        $MD5 = ((& $certUtil -hashfile "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.raw" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()
                        Write-Output "[Info]  MD5 Hash: $MD5"
                        Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $MD5 > "$OUTPUT_FOLDER\Memory\WinPMEM\MD5.txt"
                        $EndTime_MD5 = (Get-Date)
                        $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                        ('MD5 Calculation duration:    {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\WinPMEM\Stats.txt"
                    }
                }
            }

            # Creating Secure Archive File
            if (Test-Path "$7za") 
            {
                if (Test-Path "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.raw") 
                {
                    $StartTime_Archive = (Get-Date)
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... "
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.7z" "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.raw" "$OUTPUT_FOLDER\Memory\WinPMEM\MD5.txt" > $null 2>&1
                    $EndTime_Archive = (Get-Date)
                    $Time_Archive = ($EndTime_Archive-$StartTime_Archive)
                    ('Archive Creation duration:   {0} h {1} min {2} sec' -f $Time_Archive.Hours, $Time_Archive.Minutes, $Time_Archive.Seconds) >> "$OUTPUT_FOLDER\Memory\WinPMEM\Stats.txt"

                    # Remove all files except "$env:COMPUTERNAME.7z", "Stats.txt", "stdout.txt" and "stderr.txt"
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\WinPMEM" -Exclude "$env:COMPUTERNAME.7z*", "Stats.txt", "stdout.txt", "stderr.txt" -Recurse -Force | ForEach-Object ($_) {Remove-Item $_.FullName}

                    # Get File Size of "$env:COMPUTERNAME.7z"
                    $Length = (Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\WinPMEM" -Exclude *.txt | Measure-Object -Property Length -Sum).Sum
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Total Archive Size: $Size"
                    Write-Output "[Info]  Total Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Create Time (ISO 8601)
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.7z").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Last Modified Time (ISO 8601)
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\WinPMEM\$env:COMPUTERNAME.7z").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }
            else
            {
                Write-Output "[Error] 7za.exe NOT found."
                Write-Output "[Error] 7za.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        # x64
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
        {
            Write-Output "[Error] winpmem_mini_x64_rc2.exe NOT found."
            Write-Output "[Error] winpmem_mini_x64_rc2.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }

        # x86
        if ($env:PROCESSOR_ARCHITECTURE -eq "x86")
        {
            Write-Output "[Error] winpmem_mini_x86.exe NOT found."
            Write-Output "[Error] winpmem_mini_x86.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
}

# WinPMEM
if ($Tool -eq "-WinPMEM")
{
    New-WinPMEMSnapshot
}

#endregion WinPMEM

#############################################################################################################################################################################################

#region Belkasoft

Function New-BelkasoftSnapshot
{
    # ARM64 Support
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
    {
        Write-Output "[Error] ARM64 architecture is NOT supported by Belkasoft Live RAM Capturer."
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # Belkasoft Live RAM Capturer
    if (Test-Path "$Belkasoft") 
    {
        # Verify File Integrity
        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
        $MD5 = (((& $certUtil -hashfile "$Belkasoft" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()).ToUpper()

        # x64 or x86
        if (($MD5 -eq "E331F960CDBA675DEA9218EFDED56A5F") -Or ($MD5 -eq "FCA60980F235B4EFB3C3119EF4584FFF"))
        {
            # Get Physical Memory Size
            if ($PSVersionTable.PSVersion.Major -ge 3)
            {
                $TotalMemory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                $TotalMemory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {"{0}" -f ([math]::round(($_.Sum / 1GB)))}
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB"
                Write-Output "[Info]  Total Physical Memory Size: $TotalMemory GB" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Check Available Space (GB)
            $DriveLetter = "$SCRIPT_DIR".Substring(0,2)
            $AvailableSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "deviceid='$DriveLetter'" | Select-Object FreeSpace).FreeSpace | ForEach-Object {"{0}" -f ([math]::round(($_ / 1GB)))}
            
            [int]$TotalMemoryInt32 = [convert]::ToInt32($TotalMemory, 10)
            [int]$AvailableSpaceInt32 = [convert]::ToInt32($AvailableSpace, 10)
            [int]$AdditionalSpaceInt32 = ($TotalMemoryInt32/100*12.5) # +12,5%
            [int]$RequiredSpaceInt32 = ([int]$TotalMemoryInt32)+([int]$AdditionalSpaceInt32)

            if ($RequiredSpaceInt32 -gt $AvailableSpaceInt32)
            {
                Write-Output "[Error] Not enough disk space to save memory dump file."
                Write-Output "[Error] Not enough disk space to save memory dump file." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                Write-Output ""
                $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
                Exit
            }

            # Check if output directory exists
            if (Test-Path $OUTPUT_FOLDER\Memory\Belkasoft)
            {
                # Check for output directory content
                if (Test-Path $OUTPUT_FOLDER\Memory\Belkasoft\*)
                {
                    # Delete output directory content after confirmation
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Belkasoft" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -Confirm
                }
            }
            else 
            {
                # Creating Output Directory
                New-Item "$OUTPUT_FOLDER\Memory\Belkasoft" -ItemType Directory -Force | Out-Null
            }

            # Raw Physical Memory Dump
            $StartTime_MemoryAcquisition = (Get-Date)
            Write-Output "[Info]  Creating Memory Snapshot w/ Belkasoft Live RAM Capturer (Raw Physical Memory Dump) [approx. 1-6 min] ... "
            Write-Output "[Info]  Creating Memory Snapshot w/ Belkasoft Live RAM Capturer (Raw Physical Memory Dump) [approx. 1-6 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $FileName = (Get-Date).ToString("yyyyMMdd")
            Start-Process -FilePath $Belkasoft -ArgumentList "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.mem" -WindowStyle Hidden -Wait
            $EndTime_MemoryAcquisition = (Get-Date)
            $Time_MemoryAcquisition = ($EndTime_MemoryAcquisition-$StartTime_MemoryAcquisition)
            ('Memory Acquisition duration: {0} h {1} min {2} sec' -f $Time_MemoryAcquisition.Hours, $Time_MemoryAcquisition.Minutes, $Time_MemoryAcquisition.Seconds) >> "$OUTPUT_FOLDER\Memory\Belkasoft\Stats.txt"

            # Collecting PageFile
            if ($PageFile -eq "--PageFile")
            {
                Get-Pagefile
            }

            # MD5 Calculation
            if (Test-Path "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.mem") 
            {
                if (Get-Command Get-FileHash -ErrorAction SilentlyContinue)
                {
                    Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... "
                    Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    $StartTime_MD5 = (Get-Date)
                    $MD5 = (Get-FileHash -LiteralPath "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.mem" -Algorithm MD5).Hash
                    Write-Output "[Info]  MD5 Hash: $MD5"
                    Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    $MD5 > "$OUTPUT_FOLDER\Memory\Belkasoft\MD5.txt"
                    $EndTime_MD5 = (Get-Date)
                    $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                    ('MD5 Calculation duration:    {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\Belkasoft\Stats.txt"
                }
                else
                {
                    if (Test-Path "$env:SystemDrive\Windows\System32\certutil.exe")
                    {
                        Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... "
                        Write-Output "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 3-5 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $StartTime_MD5 = (Get-Date)
                        $certUtil = "$env:SystemDrive\Windows\System32\certutil.exe"
                        $MD5 = ((& $certUtil -hashfile "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.mem" MD5) -replace '\s', '' | Select-String -Pattern "^[0-9a-f]{32}$" | Out-String).Trim()
                        Write-Output "[Info]  MD5 Hash: $MD5"
                        Write-Output "[Info]  MD5 Hash: $MD5" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                        $MD5 > "$OUTPUT_FOLDER\Memory\Belkasoft\MD5.txt"
                        $EndTime_MD5 = (Get-Date)
                        $Time_MD5 = ($EndTime_MD5-$StartTime_MD5)
                        ('MD5 Calculation duration:    {0} h {1} min {2} sec' -f $Time_MD5.Hours, $Time_MD5.Minutes, $Time_MD5.Seconds) >> "$OUTPUT_FOLDER\Memory\Belkasoft\Stats.txt"
                    }
                }
            }

            # Creating Secure Archive File
            if (Test-Path "$7za") 
            {
                if (Test-Path "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.mem") 
                {
                    $StartTime_Archive = (Get-Date)
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... "
                    Write-Output "[Info]  Compressing Memory Snapshot [time-consuming task] [approx. 10-60 min] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                    & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.7z" "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.mem" "$OUTPUT_FOLDER\Memory\Belkasoft\MD5.txt" > $null 2>&1
                    $EndTime_Archive = (Get-Date)
                    $Time_Archive = ($EndTime_Archive-$StartTime_Archive)
                    ('Archive Creation duration:   {0} h {1} min {2} sec' -f $Time_Archive.Hours, $Time_Archive.Minutes, $Time_Archive.Seconds) >> "$OUTPUT_FOLDER\Memory\Belkasoft\Stats.txt"

                    # Remove all files except "$FileName.7z" and "Stats.txt"
                    Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Belkasoft" -Exclude "$FileName.7z*", "Stats.txt" -Recurse -Force | ForEach-Object ($_) {Remove-Item $_.FullName}

                    # Get File Size of "$FileName.7z"
                    $Length = (Get-ChildItem -Path "$OUTPUT_FOLDER\Memory\Belkasoft" -Exclude *.txt | Measure-Object -Property Length -Sum).Sum
                    $Size = Get-FileSize($Length)
                    Write-Output "[Info]  Total Archive Size: $Size"
                    Write-Output "[Info]  Total Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Create Time (ISO 8601)
                    $CreationTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.7z").CreationTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Create Time: $CreationTime"
                    Write-Output "[Info]  Create Time: $CreationTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

                    # Last Modified Time (ISO 8601)
                    $LastWriteTime = ((Get-Item -LiteralPath "$OUTPUT_FOLDER\Memory\Belkasoft\$FileName.7z").LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss UTC")
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime"
                    Write-Output "[Info]  Last Modified Time: $LastWriteTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }
            else
            {
                Write-Output "[Error] 7za.exe NOT found."
                Write-Output "[Error] 7za.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
        }
        else
        {
            Write-Output "[Error] File Hash does NOT match."
            Write-Output "[Error] File Hash does NOT match." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        # x64
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
        {
            Write-Output "[Error] RamCapture64.exe NOT found."
            Write-Output "[Error] RamCapture64.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }

        # x86
        if ($env:PROCESSOR_ARCHITECTURE -eq "x86")
        {
            Write-Output "[Error] RamCapture.exe NOT found."
            Write-Output "[Error] RamCapture.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
}

# Belkasoft Live RAM Capturer
if ($Tool -eq "-Belkasoft")
{
    New-BelkasoftSnapshot
}

#endregion Belkasoft

#############################################################################################################################################################################################

#region SystemInfo

# System-Info
New-Item "$OUTPUT_FOLDER\System-Info" -ItemType Directory -Force | Out-Null

# PowerShell Version
$PSVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
$ConstrainedLanguageMode = $ExecutionContext.SessionState.LanguageMode
Write-Output "[Info]  PowerShell Version: $PSVersion ($ConstrainedLanguageMode)"
Write-Output "[Info]  PowerShell Version: $PSVersion ($ConstrainedLanguageMode)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# .NET Framework Version
if (Test-Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")
{
    if (Test-RegistryValue -Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Value "Version")
    {
        $NetVersion = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Version).Version
        Write-Output "[Info]  NET Framework Version: $NETVersion"
        Write-Output "[Info]  NET Framework Version: $NETVersion" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}
else
{
    if (Test-RegistryValue -Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5" -Value "Version")
    {
        $NetVersion = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5" -Name Version).Version
        Write-Output "[Info]  NET Framework Version: $NETVersion"
        Write-Output "[Info]  NET Framework Version: $NETVersion" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# Velociraptor
$CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
if (Test-Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Services\Velociraptor")
{
    Write-Output "[Info]  Velociraptor Service found"
}

# Cortex XDR (Palo Alto Networks)
$CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
if (Test-Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Services\cyserver")
{
    # Cortex XDR Service
    $ImagePath = ((Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Services\cyserver" -Name ImagePath).ImagePath) -replace '"', ""
    if (Test-Path "$ImagePath")
    {
        $DisplayName = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Services\cyserver" -Name DisplayName).DisplayName
        $ProductVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Cyvera\Client" -Name "Product Version")."Product Version"
        Write-Output "[Info]  $DisplayName v$ProductVersion"
        Write-Output "[Info]  $DisplayName v$ProductVersion" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# CrowdStrike Agent Version
if (Test-Path "$env:SystemDrive\Windows\System32\drivers\CrowdStrike\CSAgent.sys")
{
    $CSAgent = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:SystemDrive\Windows\System32\drivers\CrowdStrike\CSAgent.sys").FileVersion
    Write-Output "[Info]  CrowdStrike Agent Version: $CSAgent"
    Write-Output "[Info]  CrowdStrike Agent Version: $CSAgent" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# CrowdStrike Agent-ID
$CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
if (Test-Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Services\CSAgent\Sim")
{
    $AID = ('{0:x}' -f ((Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Services\CSAgent\Sim" -Name AG).AG) -replace '\s','')
    Write-Output "[Info]  Agent-ID: $AID"
}

# FireEye Endpoint Security
if (Test-Path "$env:SystemDrive\Program Files (x86)\FireEye\xagt\xagt.exe")
{
    # Agent Version
    $AgentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:SystemDrive\Program Files (x86)\FireEye\xagt\xagt.exe").FileVersion
    Write-Output "[Info]  FireEye Endpoint Security v$AgentVersion"
    Write-Output "[Info]  FireEye Endpoint Security v$AgentVersion" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # Agent ID
    $xagt = "C:\Program Files (x86)\FireEye\xagt\xagt.exe"
    $AgentID = (& $xagt -G -L 20 | Select-String -Pattern "aid" | Select-Object -First 1 | ForEach-Object { -split $_.Line | Select-Object -Last 1 }).TrimEnd('.')
    Write-Output "[Info]  Agent-ID: $AgentID"
    Write-Output "[Info]  Agent-ID: $AgentID" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# Cybereason EDR
if (Test-Path "HKLM:\SOFTWARE\Cybereason")
{
    # Cybereason Sensor
    $EDRProductName = (Get-ItemProperty "HKLM:\SOFTWARE\Cybereason\ActiveProbe" -Name EDRProductName).EDRProductName
    $Version = (Get-ItemProperty "HKLM:\SOFTWARE\Cybereason\Cybereason Sensor\*\Setup" -Name Version).Version
    Write-Output "[Info]  EDR ProductName: $EDRProductName (Version: $Version)"
    Write-Output "[Info]  EDR ProductName: $EDRProductName (Version: $Version)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# ASGARD Agent v2 (Nextron Systems GmbH)
if (Test-Path "$env:SystemDrive\Windows\System32\asgard2-agent\asgard2-agent.exe")
{
    # Version
    $Agent = "$env:SystemDrive\Windows\System32\asgard2-agent\asgard2-agent.exe"
    $Version = (& $Agent -version)
    Write-Output "[Info]  Nextron Systems ASGARD Agent v2 (Version: $Version)"
    Write-Output "[Info]  Nextron Systems ASGARD Agent v2 (Version: $Version)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# McAfee Endpoint Security (ENS)
if (Test-Path "HKLM:\SOFTWARE\McAfee\Endpoint\AV")
{
    # ProductVersion
    $ProductVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\Endpoint\AV" -Name ProductVersion).ProductVersion
    Write-Output "[Info]  McAfee Endpoint Security v$ProductVersion"
    Write-Output "[Info]  McAfee Endpoint Security v$ProductVersion" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # LogFilePath
    $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
    $LogFilePath = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment" -Name "DEFLOGDIR").DEFLOGDIR
    Write-Output "[Info]  LogFilePath: $LogFilePath"
    Write-Output "[Info]  LogFilePath: $LogFilePath" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # QuarantineDirectory
    $QuarantineDirectory = (Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\AVSolution\MCSHIELDGLOBAL\MCSHIELDGLOBAL" -Name backupdirectory).backupdirectory
    Write-Output "[Info]  QuarantineDirectory: $QuarantineDirectory"
    Write-Output "[Info]  QuarantineDirectory: $QuarantineDirectory" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # QuarantineAge (in days)
    $QuarantineAge = (Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\Endpoint\AV\QM" -Name QuarantineAge).QuarantineAge
    Write-Output "[Info]  QuarantineAge (in days): $QuarantineAge"
    Write-Output "[Info]  QuarantineAge (in days): $QuarantineAge" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # Quarantine Files (PW: infected)
    if (Test-Path "$QuarantineDirectory\quarantine\*.zip")
    {
        $QuarantineFiles = Get-ChildItem "$QuarantineDirectory\quarantine\*.zip" | Measure-Object | ForEach-Object{$_.Count}
        Write-Output "[Alert] $QuarantineFiles McAfee Quarantine file(s) found"
        Write-Output "[Alert] $QuarantineFiles McAfee Quarantine file(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  No McAfee Quarantine file(s) found"
        Write-Output "[Info]  No McAfee Quarantine file(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }

    # Last Full Scan
    $LastFullScanOdsRunTime = (Get-ItemProperty "HKLM:\SOFTWARE\McAfee\Endpoint\AV\ODS" -Name LastFullScanOdsRunTime).LastFullScanOdsRunTime
    $LastFullScan = (Get-Date '1/1/1970').AddSeconds($LastFullScanOdsRunTime).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "[Info]  Last Full Scan: $LastFullScan UTC"
    Write-Output "[Info]  Last Full Scan: $LastFullScan UTC" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# McAfee VirusScan Enterprise (VSE)
if (Test-Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\AVEngine")
{
    # Version
    $Version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\DesktopProtection" -Name szProductVer).szProductVer
    $Patch = ((Get-Item -Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\DesktopProtection" | Select-Object -ExpandProperty Property | Select-String -Pattern "Patch_") -replace "_"," " | Out-String).Trim()
    Write-Output "[Info]  McAfee VirusScan Enterprise v$Version (Patch: $Patch)"
    Write-Output "[Info]  McAfee VirusScan Enterprise v$Version (Patch: $Patch)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # LogFilePath
    $CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
    $LogFilePath = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment" -Name "DEFLOGDIR").DEFLOGDIR
    Write-Output "[Info]  LogFilePath: $LogFilePath"
    Write-Output "[Info]  LogFilePath: $LogFilePath" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # QuarantineDirectory
    $QuarantineDirectory = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\DesktopProtection" -Name QuarantineDirectory).QuarantineDirectory
    Write-Output "[Info]  QuarantineDirectory: $QuarantineDirectory"
    Write-Output "[Info]  QuarantineDirectory: $QuarantineDirectory" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # QuarantineAge (in days)
    $QuarantineAge = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\DesktopProtection" -Name QuarantineAge).QuarantineAge
    Write-Output "[Info]  QuarantineAge (in days): $QuarantineAge"
    Write-Output "[Info]  QuarantineAge (in days): $QuarantineAge" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # Quarantine Files
    if (Test-Path "$QuarantineDirectory\*.bup")
    {
        $BUPFILES = Get-ChildItem "$QuarantineDirectory\*.bup" | Measure-Object | ForEach-Object{$_.Count}
        Write-Output "[Alert] $BUPFILES McAfee Quarantine file(s) found"
        Write-Output "[Alert] $BUPFILES McAfee Quarantine file(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  No McAfee Quarantine file(s) found"
        Write-Output "[Info]  No McAfee Quarantine file(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# Trend Micro Apex One
if (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ApexOneNT")
{
    # Version
    $Version = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ApexOneNT" -Name DisplayVersion).DisplayVersion).split("\.")[0,1] -join "."
    $Build = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ApexOneNT" -Name DisplayVersion).DisplayVersion).split("\.")[-1]
    Write-Output "[Info]  Trend Micro Apex One $Version (Build: $Build)"
    Write-Output "[Info]  Trend Micro Apex One $Version (Build: $Build)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # Agent Installation Folder
    $InstallPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\TrendMicro\Osprey" -Name InstallPath).InstallPath
    Write-Output "[Info]  Agent Installation Folder: $InstallPath"
    Write-Output "[Info]  Agent Installation Folder: $InstallPath" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

    # QuarantineDirectory
    if (Test-Path "$InstallPath\SUSPECT\Backup\*.qtn")
    {
        $QTNFILES = Get-ChildItem "$InstallPath\SUSPECT\Backup\*.qtn" | Measure-Object | ForEach-Object{$_.Count}
        Write-Output "[Alert] $QTNFILES Trend Micro Quarantine file(s) found"
        Write-Output "[Alert] $QTNFILES Trend Micro Quarantine file(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  No Trend Micro Quarantine file(s) found"
        Write-Output "[Info]  No Trend Micro Quarantine file(s) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# Sophos Endpoint Security and Control (SESC) --> Sophos Anti-Virus (SAV)
if (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Application")
{
    # Version
    $Version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Telemetry\Install" -Name Version).Version

    # UpToDateState
    $UpToDateState = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Status" -Name UpToDateState).UpToDateState

    # 1 - TRUE
    
    Write-Output "[Info]  Sophos Anti-Virus $Version (UpToDateState: $UpToDateState)"

    # LastUpdateTime
    $LastUpdateTime = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Status" -Name LastUpdateTime).LastUpdateTime
    $TimestampUtc = (([System.DateTimeOffset]::FromUnixTimeSeconds($LastUpdateTime)).DateTime).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output = "[Info]  LastUpdateTime: $TimestampUtc UTC"

    # Features
    $Features = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Telemetry\Install" -Name Features).Features
    Write-Output "[Info]  Features: $Features"

    # AV        - Anti-Virus
    # CRT       - Competitor Removal Tool (detects third-party security software)
    # DLP       - Data Leakage Prevention
    # DVCCNTRL  - Device Control
    # HIPS      - Host Intrusion Prevention
    # PUA       - Potentially Unwanted Applications
    # URLSCRTY  - URL-Filtering (Web Protection)
    # WEBCNTRL  - Web Control

    # LogDir
    $LogDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Application" -Name LogDir).LogDir
    Write-Output "[Info]  LogDir: $LogDir"

    # DBFolder
    $DBFolder = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Safestore" -Name DBFolder).DBFolder
    Write-Output "[Info]  DBFolder: $DBFolder"

    # SafestoreCount
    $SafestoreCount = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\Telemetry\Safestore" -Name store_count).store_count
    Write-Output "[Info]  SafestoreCount: $SafestoreCount"
}

# Microsoft Defender for Endpoint
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection")
{
    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value "OnboardingState")
    {
        if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OnboardingState) -eq $True)
        {
            # OnboardingState
            $OnboardingState = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name OnboardingState).OnboardingState

            if ($OnboardingState -match "1")
            {
                Write-Output "[Info]  Microsoft Defender for Endpoint (OnboardingState: 1)"
                Write-Output "[Info]  Microsoft Defender for Endpoint (OnboardingState: 1)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                Write-Output "[Info]  Microsoft Defender for Endpoint (OnboardingState: 0)"
                Write-Output "[Info]  Microsoft Defender for Endpoint (OnboardingState: 0)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # senseId
            $senseId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Name senseId).senseId
            Write-Output "[Info]  senseId: $senseId"
            Write-Output "[Info]  senseId: $senseId" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

            # senseGuid
            $senseGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Name senseGuid).senseGuid
            Write-Output "[Info]  senseGuid: $senseGuid"
            Write-Output "[Info]  senseGuid: $senseGuid" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

            # OrgId
            $OrgId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name OrgId).OrgId
            Write-Output "[Info]  OrgId: $OrgId"
            Write-Output "[Info]  OrgId: $OrgId" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

            # LastConnected
            $LastConnected = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name LastConnected).LastConnected
            $TimestampUtc = [datetime]::FromFileTime($LastConnected).ToString("yyyy-MM-dd HH:mm:ss")
            Write-Output "[Info]  LastConnected: $TimestampUtc"
            Write-Output "[Info]  LastConnected: $TimestampUtc" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        }
    }
}

# Microsoft Defender AntiVirus
if (Get-Command -CommandType Function Get-MpComputerStatus -ErrorAction SilentlyContinue)
{
    New-Item "$OUTPUT_FOLDER\System-Info\Microsoft-Defender" -ItemType Directory -Force | Out-Null

    # MpComputerStatus
    Get-MpComputerStatus -ErrorAction SilentlyContinue| Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\MpComputerStatus.txt"

    # Real-Time Monitoring
    $RealTimeProtectionEnabled = (Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
    if ($IsTamperProtected)
    {
        $RealTimeProtectionEnabled | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\RealTimeProtectionEnabled.txt"
    }

    # Tamper Protection
    $IsTamperProtected = (Get-MpComputerStatus | Select-Object IsTamperProtected -ErrorAction SilentlyContinue).IsTamperProtected
    if ($IsTamperProtected)
    {
        $IsTamperProtected | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\IsTamperProtected.txt"
    }

    # AMRunningMode
    $AMRunningMode = (Get-MpComputerStatus | Select-Object AMRunningMode -ErrorAction SilentlyContinue).AMRunningMode
    if ($AMRunningMode)
    {
        $AMRunningMode | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\AMRunningMode.txt"
    }

    # Normal means Microsoft Defender Antivirus is running in active mode.
    # Passive mode means Microsoft Defender Antivirus running, but is not the primary antivirus/antimalware product on your device. Passive mode is only available for devices that are onboarded to Microsoft Defender for Endpoint and that meet certain requirements.
    # EDR Block Mode means Microsoft Defender Antivirus is running and Endpoint detection and response (EDR) in block mode, a capability in Microsoft Defender for Endpoint, is enabled. Check the ForceDefenderPassiveMode registry key. If its value is 0, it is running in normal mode; otherwise, it is running in passive mode.
    # SxS Passive Mode means Microsoft Defender Antivirus is running alongside another antivirus/antimalware product, and limited periodic scanning is used.

    # IsVirtualMachine (True/False)
    $IsVirtualMachine = (Get-MpComputerStatus | Select-Object IsVirtualMachine -ErrorAction SilentlyContinue).IsVirtualMachine
    if ($IsVirtualMachine)
    {
        $IsVirtualMachine | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\IsVirtualMachine.txt"
    }

    # MpPreference
    if (Get-Command -Name Get-MpPreference -CommandType Function -ErrorAction SilentlyContinue)
    {
        Get-MpPreference | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Get-MpPreference.txt"

        # Exclusions
        New-Item "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Exclusions" -ItemType Directory -Force | Out-Null

        # ExclusionPath
        $ExclusionPath = (Get-MpPreference | Select-Object ExclusionPath).ExclusionPath
        if ($ExclusionPath)
        {
            $ExclusionPath | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Exclusions\ExclusionPath.txt"
        }

        # ExclusionExtension
        $ExclusionExtension = (Get-MpPreference | Select-Object ExclusionExtension).ExclusionExtension
        if ($ExclusionExtension)
        {
            $ExclusionExtension | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Exclusions\ExclusionExtension.txt"
        }

        # ExclusionIpAddress
        $ExclusionIpAddress = (Get-MpPreference | Select-Object ExclusionIpAddress -ErrorAction SilentlyContinue).ExclusionIpAddress
        if ($ExclusionIpAddress)
        {
            $ExclusionIpAddress | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Exclusions\ExclusionIpAddress.txt"
        }

        # ExclusionProcess
        $ExclusionProcess = (Get-MpPreference | Select-Object ExclusionProcess -ErrorAction SilentlyContinue).ExclusionProcess
        if ($ExclusionProcess)
        {
            $ExclusionProcess | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Exclusions\ExclusionProcess.txt"
        }
    }

    # Gets active and past malware threats that Windows Defender detected
    Get-MpThreatDetection -ErrorAction SilentlyContinue | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Get-MpThreatDetection.txt"

    # Gets the history of threats detected on the computer
    Get-MpThreat -ErrorAction SilentlyContinue | Out-File "$OUTPUT_FOLDER\System-Info\Microsoft-Defender\Get-MpThreat.txt"
}

# Get-SecurityProduct
Function Get-SecurityProduct 
{
    # AntiVirusProduct
    if (Get-WmiObject -List -Namespace "root\SecurityCenter2" -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "AntiVirusProduct"})
    {
        $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

        if ($AntiVirusProducts) 
        {
            $AntiVirus = @()
            ForEach($AntiVirusProduct in $AntiVirusProducts)
            {
                # Switch to determine the status of Anti-Virus definitions and Real-Time Protection
                switch ($AntiVirusProduct.productState) 
                {
                    "262144" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "Yes" } # McAfee Endpoint Security (ENS)
                    "262160" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "No" }
                    "266240" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"} # McAfee Endpoint Security (ENS)
                    "266256" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "No"}
                    "393216" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "Yes"}  # Microsoft Security Essentials, McAfee Endpoint Security (ENS)
                    "393232" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "No"}
                    "393472" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "Yes"}  # Windows Defender
                    "393488" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "No"}
                    "397312" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"} # Microsoft Security Essentials, McAfee Endpoint Security (ENS)
                    "397328" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "No"}  # McAfee Endpoint Security (ENS)
                    "397568" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"} # Windows Defender
                    "397584" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "No"}  # Windows Defender
                    "401664" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"} # Windows Defender
                    default {$RealTimeProtectionStatus = "Unknown"; $DefinitionStatus = "Unknown"}
                }

                $AV = @{}
                $AV.'Display Name' = $AntiVirusProduct.displayName
                $AV.'Instance GUID' = $AntiVirusProduct.instanceGuid
                $AV.'Product State' = $AntiVirusProduct.productState
                $AV.'Enabled' = $RealTimeProtectionStatus
                $AV.'Up To Date' = $DefinitionStatus
                $AV.'Product Type' = "AntiVirusProduct"
                $AV.'Product EXE' = $AntiVirusProduct.pathToSignedProductExe
                $AV.'Reporting EXE' = $AntiVirusProduct.pathToSignedReportingExe

                $AntiVirus += New-Object -TypeName PSObject -Property $AV
            }

            New-Item "$OUTPUT_FOLDER\System-Info\Get-SecurityProduct" -ItemType Directory -Force | Out-Null
            $AntiVirus | Select-Object "Display Name","Instance GUID","Product State","Enabled","Up To Date","Product Type","Product EXE","Reporting EXE" | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\System-Info\Get-SecurityProduct\SecurityProducts.csv"
        }
    }

    # AntiSpywareProduct
    if (Get-WmiObject -List -Namespace "root\SecurityCenter2" -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "AntiSpywareProduct"})
    {
        $AntiSpywareProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiSpywareProduct

        if ($AntiSpywareProducts) 
        {
            $AntiSpyware = @()
            ForEach($AntiSpywareProduct in $AntiSpywareProducts)
            {
                switch ($AntiSpywareProduct.productState) 
                {
                    "262144" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "Yes" }
                    "262160" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "No" }
                    "266240" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"}
                    "266256" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "No"}
                    "393216" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "Yes"}
                    "393232" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "No"}
                    "393472" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "Yes"}
                    "393488" {$RealTimeProtectionStatus = "No"; $DefinitionStatus = "No"}
                    "397312" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"}
                    "397328" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "No"}
                    "397568" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"}
                    "397584" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "No"}
                    "401664" {$RealTimeProtectionStatus = "Yes"; $DefinitionStatus = "Yes"}
                    default {$RealTimeProtectionStatus = "Unknown"; $DefinitionStatus = "Unknown"}
                }

                $AS = @{}
                $AS.'Display Name' = $AntiSpywareProduct.displayName
                $AS.'Instance GUID' = $AntiSpywareProduct.instanceGuid
                $AS.'Product State' = $AntiSpywareProduct.productState
                $AS.'Enabled' = $RealTimeProtectionStatus
                $AS.'Up To Date' = $DefinitionStatus
                $AS.'Product Type' = "AntiSpywareProduct"
                $AS.'Product EXE' = $AntiSpywareProduct.pathToSignedProductExe
                $AS.'Reporting EXE' = $AntiSpywareProduct.pathToSignedReportingExe

                $AntiSpyware += New-Object -TypeName PSObject -Property $AS
            }

            New-Item "$OUTPUT_FOLDER\System-Info\Get-SecurityProduct" -ItemType Directory -Force | Out-Null
            $AntiSpyware | Select-Object "Display Name","Instance GUID","Product State","Enabled","Up To Date","Product Type","Product EXE","Reporting EXE" | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Select-Object -Skip 1 | Out-File "$OUTPUT_FOLDER\System-Info\Get-SecurityProduct\SecurityProducts.csv" -Append 
        }
    }
}

Get-SecurityProduct

# ProductName
if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "ProductName")
{
    $ProductName = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName)
}

# OSArchitecture
$OSArchitecture = ( (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture )

if ($OSArchitecture -like "*64*")
{
    $OSArchitecture = "64-Bit"
}
else
{
    $OSArchitecture = "32-Bit"
}

# Processor Architecture

# ARM
if ($env:PROCESSOR_ARCHITECTURE -like "*ARM*")
{
    $ProcessorArchitecture = "ARM-based Processor"
}

# AMD64
if ($env:PROCESSOR_ARCHITECTURE -like "*AMD64*")
{
    $ProcessorArchitecture = "x64-based Processor"
}

# x86
if ($env:PROCESSOR_ARCHITECTURE -like "*x86*")
{
    $ProcessorArchitecture = "x86-based Processor"
}

# CSDVersion
if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "CSDVersion")
{
    $OSVersion = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CSDVersion).CSDVersion)
}

# Windows 10
if ($ProductName -like "*Windows 10*")
{
    # Major
    $Major = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentMajorVersionNumber).CurrentMajorVersionNumber)

    # Minor
    $Minor = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentMinorVersionNumber).CurrentMinorVersionNumber)
}
else 
{
    # CurrentVersion
    $CurrentVersion = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentVersion).CurrentVersion)

    # Major
    $Major = $CurrentVersion.split('.')[0]

    # Minor
    $Minor = $CurrentVersion.split('.')[1]
}

# Windows 10, Windows 11, Windows Server 2016, Windows Server 2019, and Windows Server 2022
if (($ProductName -like "*Windows 10*") -Or ($ProductName -like "*Windows Server 2016*") -Or ($ProductName -like "*Windows Server 2019*") -Or ($ProductName -like "*Windows Server 2022*"))
{
    # DisplayVersion
    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "DisplayVersion")
    {
        $DisplayVersion = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion)
    }

    # ReleaseID
    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "ReleaseID")
    {
        $ReleaseID = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseID).ReleaseID)
    }

    # CurrentBuildNumber
    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "CurrentBuildNumber")
    {
        $CurrentBuildNumber = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber).CurrentBuildNumber)
    }

    # UBR (Update Build Revision)
    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "UBR")
    {
        $UBR = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR).UBR)
    }

    # Windows 11 (CurrentBuildNumber + Update Build Revision)
    # Windows 11 Build 21996 --> First Developer Preview
    # Windows 11 Build 22000 --> First Public Preview
    if ($CurrentBuildNumber -ge "21996")
    {
        $ProductName = $ProductName | ForEach-Object{($_ -replace "10","11")}
        Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$UBR)"
        Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$UBR)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append


        # System Type
        Write-Output "[Info]  System Type: $OSArchitecture Operating System, $ProcessorArchitecture"
        Write-Output "[Info]  System Type: $OSArchitecture Operating System, $ProcessorArchitecture" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        if ($DisplayVersion)
        {
            Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $ReleaseID / $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$UBR)"
            Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $ReleaseID / $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$UBR)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        }
        else
        {
            Write-Output "[Info]  OS: $ProductName, Version: $ReleaseID ($Major.$Minor.$CurrentBuildNumber.$UBR)"
            Write-Output "[Info]  OS: $ProductName, Version: $ReleaseID ($Major.$Minor.$CurrentBuildNumber.$UBR)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

            # System Type
            Write-Output "[Info]  System Type: $OSArchitecture Operating System, $ProcessorArchitecture"
            Write-Output "[Info]  System Type: $OSArchitecture Operating System, $ProcessorArchitecture" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        }
    }
}
else
{
    # CurrentBuildNumber
    $CurrentBuildNumber = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber).CurrentBuildNumber)

    # Revision Number
    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "BuildLabEx")
    {
        # BuildLabEx
        $BuildLabEx = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name BuildLabEx).BuildLabEx)
        $RevisionNumber = $BuildLabEx.split('.')[1]
    }
    else
    {
        if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "BuildLab")
        {
            # BuildLab
            $BuildLab = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name BuildLab).BuildLab)
            $RevisionNumber = $BuildLab.split('-')[1]
        }
    }

    if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "CSDVersion")
    {
        Write-Output "[Info]  OS: $ProductName ($OSArchitecture), $OSVersion ($Major.$Minor.$CurrentBuildNumber.$RevisionNumber)"
        Write-Output "[Info]  OS: $ProductName ($OSArchitecture), $OSVersion ($Major.$Minor.$CurrentBuildNumber.$RevisionNumber)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $Major.$Minor (Build: $CurrentBuildNumber.$RevisionNumber)"
        Write-Output "[Info]  OS: $ProductName ($OSArchitecture), Version: $Major.$Minor (Build: $CurrentBuildNumber.$RevisionNumber)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# InstallDate (ISO 8601)
$OS = Get-WmiObject -class Win32_OperatingSystem
$InstallDate = ( $OS.ConvertToDateTime($OS.InstallDate).ToString("yyyy-MM-dd HH:mm:ss") )
Write-Output "[Info]  InstallDate: $InstallDate UTC"
Write-Output "[Info]  InstallDate: $InstallDate UTC" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# InstallDates (MM/dd/yyyy)
(Get-ChildItem "HKLM:\SYSTEM\Setup\Source OS*" | ForEach-Object {Get-ItemProperty $_.PSPath | Select-Object -Property PSChildName,ProductName,ReleaseId} | Sort-Object -Property ReleaseId | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\InstallDates.txt" 2> $null

# RegisteredOrganization
if ($null -ne (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("RegisteredOrganization"))
{
    $RegisteredOrganization = ( (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name RegisteredOrganization).RegisteredOrganization )
    if ($null -ne $RegisteredOrganization)
    {
        Write-Output "[Info]  RegisteredOrganization: --"
        Write-Output "[Info]  RegisteredOrganization: --" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    } 
    else 
    {
        Write-Output "[Info]  RegisteredOrganization: $RegisteredOrganization"
        Write-Output "[Info]  RegisteredOrganization: $RegisteredOrganization" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# RegisteredOwner
if ($null -ne (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("RegisteredOwner"))
{
    $RegisteredOwner = ( (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name RegisteredOwner).RegisteredOwner )
    if ($null -ne $RegisteredOwner)
    {
        Write-Output "[Info]  RegisteredOwner: --"
        Write-Output "[Info]  RegisteredOwner: --" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  RegisteredOwner: $RegisteredOwner"
        Write-Output "[Info]  RegisteredOwner: $RegisteredOwner" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# OEM Information
if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Value "Manufacturer")
{
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\OEMInformation.txt" 2> $null
}

# System Language ID
# https://docs.microsoft.com/en-us/windows/desktop/intl/language-identifier-constants-and-strings
$SystemLanguageID = ( (Get-WmiObject -class Win32_OperatingSystem).Locale )
Write-Output "[Info]  System Language ID: $SystemLanguageID (e.g. 0407 = Germany)"
Write-Output "[Info]  System Language ID: $SystemLanguageID (e.g. 0407 = Germany)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# Keyboard Layout
# https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-language-pack-default-values
# Note: This will return a list of all installed keyboards of the current user, with the one currently in use as 1.
reg query "HKEY_CURRENT_USER\Keyboard Layout\Preload" | Where-Object {$_ -ne ""} > "$OUTPUT_FOLDER\System-Info\Keyboard-Layout.txt" 2> $null

# Computer System
(Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name,Manufacturer,Model,ChassisSKUNumber,Domain,SystemType,PrimaryOwnerName | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\ComputerSystem.txt" 2> $null

# Physical Memory
(Get-WmiObject -Class Win32_PhysicalMemory | Select-Object Manufacturer,PartNumber,SerialNumber,Banklabel,Configuredclockspeed,Devicelocator,Capacity | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\PhysicalMemory.txt" 2> $null

# BIOS
(Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,Name,SerialNumber,Version,ReleaseDate | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\BIOS.txt" 2> $null

# Operating System
(Get-WmiObject -Class Win32_OperatingSystem | Select-Object Manufacturer,Caption,Version,BuildNumber,OSArchitecture,OSLanguage,Locale,SystemDrive,NumberOfProcesses | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\OperatingSystem.txt" 2> $null

# User Accounts (Local)
(Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object AccountType,Description,Status,Disabled,Caption,Domain,SID,FullName,Name,LocalAccount,Lockout,PasswordRequired,PasswordChangeable,PasswordExpires | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\UserAccounts-Local.txt" 2> $null

# Users
(Get-ChildItem -Force "$env:SystemDrive\Users\*\NTUSER.DAT" | Select-Object FullName,Length, CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc,Attributes | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\Users.txt" 2> $null

# PsLoggedOn --> No ARM64 Support
# Note: When launched for the first time, PsLoggedOn will create following regkey: HKCU\Software\Sysinternals\PsLoggedOn\EulaAccepted=0x01
if (!($env:PROCESSOR_ARCHITECTURE -eq "ARM64"))
{
    & $PsLoggedOn -accepteula > "$OUTPUT_FOLDER\System-Info\PsLoggedOn.txt"
}

# Local Users
if (Get-Command -CommandType Cmdlet Get-LocalUser -ErrorAction SilentlyContinue)
{
    Get-LocalUser | Format-Table | Out-File "$OUTPUT_FOLDER\System-Info\LocalUsers.txt" -Encoding UTF8
}

# Active Users
if (Get-Command -CommandType Application query -ErrorAction SilentlyContinue)
{
    query user > "$OUTPUT_FOLDER\System-Info\ActiveUsers.txt"
}

# Check if WMI Class exists
if (Get-WmiObject -List | Where-Object {$_.Name -eq "Win32_Printer"})
{
    # Printer
    (Get-WmiObject -Class Win32_Printer | Format-Table DeviceID,DriverName -AutoSize | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\Printer.txt" 2> $null
    Get-WmiObject -Class Win32_Printer | Select-Object DeviceID,DriverName | Export-Csv "$OUTPUT_FOLDER\System-Info\Printer.csv" -Delimiter "`t" -NoTypeInformation
}

# Virtualization-Based Security (VBS)
if (Get-Command -CommandType Cmdlet Get-CimInstance -ErrorAction SilentlyContinue)
{
    # Check if WMI Namespace exists
    if (Get-WmiObject -List -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "Win32_DeviceGuard"})
    {
        Function Get-DeviceGuardStatus
        {
            $AvailableSecurityPropertiesTable = @{
                1 = 'BaseVirtualizationSupport'
                2 = 'SecureBoot'
                3 = 'DMAProtection'
                4 = 'SecureMemoryOverwrite'
                5 = 'UEFICodeReadOnly'
                6 = 'SMMSecurityMitigations1.0'
            }

            $CodeIntegrityPolicyEnforcementStatusTable = @{
                0 = 'Off'
                1 = 'AuditMode'
                2 = 'EnforcementMode'
            }

            $SecurityServicesConfiguredTable = @{
                1 = 'CredentialGuard'
                2 = 'HypervisorEnforcedCodeIntegrity'
            }

            $VirtualizationBasedSecurityStatusTable = @{
                0 = 'Off'
                1 = 'Configured'
                2 = 'Running'
            }
            
            $DeviceGuardStatus = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard

            if ($DeviceGuardStatus) 
            {
                $AvailableSecurityProperties = $DeviceGuardStatus.AvailableSecurityProperties | ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }
                $CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.CodeIntegrityPolicyEnforcementStatus]
                $RequiredSecurityProperties = $DeviceGuardStatus.RequiredSecurityProperties | ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }
                $SecurityServicesConfigured = $DeviceGuardStatus.SecurityServicesConfigured | ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }
                $SecurityServicesRunning = $DeviceGuardStatus.SecurityServicesRunning | ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }
                $UsermodeCodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.UsermodeCodeIntegrityPolicyEnforcementStatus]
                $VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatusTable[[Int32] $DeviceGuardStatus.VirtualizationBasedSecurityStatus]
        
                $ObjectProperties = [Ordered] @{
                    AvailableSecurityProperties = $AvailableSecurityProperties
                    CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatus
                    InstanceIdentifier = $DeviceGuardStatus.InstanceIdentifier
                    RequiredSecurityProperties = $RequiredSecurityProperties
                    SecurityServicesConfigured = $SecurityServicesConfigured
                    SecurityServicesRunning = $SecurityServicesRunning
                    UsermodeCodeIntegrityPolicyEnforcementStatus = $UsermodeCodeIntegrityPolicyEnforcementStatus
                    Version = $DeviceGuardStatus.Version
                    VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatus
                }

                [PSCustomObject] $ObjectProperties
            }
        }

        $AvailableSecurityProperties = (Get-DeviceGuardStatus | Select-Object -ExpandProperty AvailableSecurityProperties) -join ', '
        $CodeIntegrityPolicyEnforcementStatus = (Get-DeviceGuardStatus | Select-Object CodeIntegrityPolicyEnforcementStatus).CodeIntegrityPolicyEnforcementStatus
        $InstanceIdentifier = (Get-DeviceGuardStatus | Select-Object InstanceIdentifier).InstanceIdentifier
        $RequiredSecurityProperties = (Get-DeviceGuardStatus | Select-Object RequiredSecurityProperties).RequiredSecurityProperties
        $SecurityServicesConfigured = (Get-DeviceGuardStatus | Select-Object SecurityServicesConfigured).SecurityServicesConfigured
        $SecurityServicesRunning = (Get-DeviceGuardStatus | Select-Object SecurityServicesRunning).SecurityServicesRunning
        $UsermodeCodeIntegrityPolicyEnforcementStatus = (Get-DeviceGuardStatus | Select-Object UsermodeCodeIntegrityPolicyEnforcementStatus).UsermodeCodeIntegrityPolicyEnforcementStatus
        $Version = (Get-DeviceGuardStatus | Select-Object Version).Version
        $VirtualizationBasedSecurityStatus = (Get-DeviceGuardStatus | Select-Object VirtualizationBasedSecurityStatus).VirtualizationBasedSecurityStatus

        Write-Output "AvailableSecurityProperties                  : $AvailableSecurityProperties" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "CodeIntegrityPolicyEnforcementStatus         : $CodeIntegrityPolicyEnforcementStatus" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "InstanceIdentifier                           : $InstanceIdentifier" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "RequiredSecurityProperties                   : $RequiredSecurityProperties" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "SecurityServicesConfigured                   : $SecurityServicesConfigured" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        write-Output "SecurityServicesRunning                      : $SecurityServicesRunning" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "UsermodeCodeIntegrityPolicyEnforcementStatus : $UsermodeCodeIntegrityPolicyEnforcementStatus" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "Version                                      : $Version" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
        Write-Output "VirtualizationBasedSecurityStatus            : $VirtualizationBasedSecurityStatus" | Out-File "$OUTPUT_FOLDER\System-Info\DeviceGuard.txt" -Append
    }
}

# Time Difference
$LocalTime = (Get-Date)
$UniversalTime = [datetime]::Now.ToUniversalTime()
$DiffHours = [math]::Round(($LocalTime - $UniversalTime).TotalHours)

if ($DiffHours)
{
    if ($DiffHours -like "*-*")
    {
        $UTC = ("UTC" + $DiffHours + ":00")
    }
    else
    {
        $UTC = ("UTC+" + $DiffHours + ":00")
    }
}

# Timezone Info
$TimeZone = ( [TimeZoneInfo]::Local.Id )
Write-Output "[Info]  Timezone Info: $TimeZone ($UTC)"
Write-Output "[Info]  Timezone Info: $TimeZone ($UTC)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# StandardName
(Get-WmiObject -Class Win32_TimeZone).StandardName > "$OUTPUT_FOLDER\System-Info\Timezone-StandardName.txt" 2> $null

# DaylightName
(Get-WmiObject -Class Win32_TimeZone).DaylightName > "$OUTPUT_FOLDER\System-Info\Timezone-DaylightName.txt" 2> $null

# Caption
(Get-WmiObject -Class Win32_TimeZone).Caption > "$OUTPUT_FOLDER\System-Info\Timezone-Caption.txt" 2> $null

# Last Logged On User
$LastLoggedOnUser = ( (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).Username -creplace '(?s)^.*\\', '' )
Write-Output "[Info]  Last Logged On User: $LastLoggedOnUser"
Write-Output "[Info]  Last Logged On User: $LastLoggedOnUser" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# Last Boot Up Time (ISO 8601)
# https://www.systanddeploy.com/2022/06/using-powershell-to-get-real-device.html
if (Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Value "HiberbootEnabled")
{
    $FastBoot = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ErrorAction SilentlyContinue).HiberbootEnabled

    if($FastBoot -eq 0)
    {
        $OS = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
        $Uptime = (Get-Date) - $OS.ConvertToDateTime($OS.LastBootUpTime)
        Write-Output ("[Info]  Last Boot: " + $OS.ConvertToDateTime($OS.LastBootUpTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC") )
        Write-Output ("[Info]  Uptime: " + $Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes" )
        Write-Output ("[Info]  Last Boot: " + $OS.ConvertToDateTime($OS.LastBootUpTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC") ) | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        Write-Output ("[Info]  Uptime: " + $Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes" ) | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    elseif($FastBoot -eq 1)
    {
        $BootEvent = Get-WinEvent -ProviderName "Microsoft-Windows-Kernel-Boot"| Where-Object {$_.ID -eq 27 -and $_.Message -like "*0x1*"} # Shutdown with fast boot
        if($null -ne $BootEvent)
        {
            $LastBoot = ($BootEvent[0].TimeCreated).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            $Uptime = New-TimeSpan -Start "$LastBoot" -End $(Get-Date)
            Write-Output "[Info]  Last Boot: $LastBoot UTC"
            Write-Output "[Info]  Last Boot: $LastBoot UTC" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            Write-Output ("[Info]  Uptime: " + $Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes" )
            Write-Output ("[Info]  Uptime: " + $Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes" ) | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        }
    }
}
else
{
    $OS = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    $Uptime = (Get-Date) - $OS.ConvertToDateTime($OS.LastBootUpTime)
    Write-Output ("[Info]  Last Boot: " + $OS.ConvertToDateTime($OS.LastBootUpTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC") )
    Write-Output ("[Info]  Uptime: " + $Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes" )
    Write-Output ("[Info]  Last Boot: " + $OS.ConvertToDateTime($OS.LastBootUpTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC") ) | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    Write-Output ("[Info]  Uptime: " + $Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes" ) | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# Active Connections
if (Get-Command -Name Get-NetTCPConnection -CommandType Function -ErrorAction SilentlyContinue)
{
    $netstat = Get-NetTCPConnection | Select-Object -Property @{N="CreationTime UTC"; E={($_.CreationTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},@{N="CreationTime"; E={($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss")}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State

    if ($netstat)
    {
        $netstat | Export-Csv "$OUTPUT_FOLDER\System-Info\netstat.csv" -NoTypeInformation
        $netstat | Format-Table -AutoSize | Out-File "$OUTPUT_FOLDER\System-Info\netstat.txt"
    }
}
else
{
    netstat | Out-File "$OUTPUT_FOLDER\System-Info\netstat.txt"
}

# Opened Files (remotely through a shared folder)
if (Get-Command -Name openfiles -CommandType Application -ErrorAction SilentlyContinue)
{
    # TXT
    openfiles | Out-File "$OUTPUT_FOLDER\System-Info\OpenFiles.txt" -Encoding UTF8

    # CSV
    (openfiles) -split "\n" -replace '\s\s+', ',' | Out-File "$OUTPUT_FOLDER\System-Info\OpenFiles.csv" -Encoding UTF8
}

# DNS Cache (useful for recent web history)
if (Get-Command -Name Get-DnsClientCache -CommandType Function -ErrorAction SilentlyContinue)
{
    $DnsClientCacheEntries = Get-DnsClientCache

    if ($DnsClientCacheEntries) 
    {
        $DnsClientCache = @()
        ForEach($DnsClientCacheEntry in $DnsClientCacheEntries)
        {
            switch ($DnsClientCacheEntry.Section) 
            {
                "1" { $SectionObject = 'Answer' }
                "2" { $SectionObject = 'Authority' }
                "3" { $SectionObject = 'Additional' }
            }

            switch ($DnsClientCacheEntry.Status) 
            {
                   "0" { $StatusObject = 'Success' }
                "9003" { $StatusObject = 'NotExist' }
                "9701" { $StatusObject = 'NoRecords' }
            }

            switch ($DnsClientCacheEntry.Type) 
            {
                 "1" { $TypeObject = 'A' }
                 "2" { $TypeObject = 'NS' }
                 "5" { $TypeObject = 'CNAME' }
                 "6" { $TypeObject = 'SOA' }
                "12" { $TypeObject = 'PTR' }
                "15" { $TypeObject = 'MX' }
                "28" { $TypeObject = 'AAAA' }
                "33" { $TypeObject = 'SRV' }
            }

            $DCC = @{}
            $DCC.Name    = $DnsClientCacheEntry.Name
            $DCC.Entry   = $DnsClientCacheEntry.Entry
            $DCC.Data    = $DnsClientCacheEntry.Data
            $DCC.Section = $SectionObject
            $DCC.Status  = $StatusObject
            $DCC.TTL     = $DnsClientCacheEntry.TTL
            $DCC.Type    = $TypeObject

            $DnsClientCache += New-Object -TypeName PSObject -Property $DCC
        }

        $DnsClientCache | Select-Object -Property Name, Entry, Data, Section, Status, TTL, Type | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\System-Info\DnsClientCache.csv"
    }
}
else
{
    ipconfig /displaydns | Out-File "$OUTPUT_FOLDER\System-Info\ipconfig-displaydns.txt" -Encoding UTF8
}

# Network ARP Info
if (Get-Command -Name Get-NetNeighbor -CommandType Function -ErrorAction SilentlyContinue)
{
    Get-NetNeighbor | Select-Object -Property InterfaceAlias, IPAddress, AddressFamily, LinkLayerAddress, State, Store | Export-Csv "$OUTPUT_FOLDER\System-Info\Network-ARP-Info.csv" -NoTypeInformation
}
else
{
    arp -a | Out-File "$OUTPUT_FOLDER\System-Info\Network-ARP-Info.txt" -Encoding UTF8
}

# IP Routing Info
if (Get-Command -Name Get-NetRoute -CommandType Function -ErrorAction SilentlyContinue)
{
    Get-NetRoute | Select-Object -Property DestinationPrefix, NextHop, RouteMetric, ifIndex, Store, State, Protocol, InterfaceAlias | Export-Csv "$OUTPUT_FOLDER\System-Info\IP-Routing-Info.csv" -NoTypeInformation
}
else
{
    route print | Out-File "$OUTPUT_FOLDER\System-Info\IP-Routing-Info.txt" -Encoding UTF8
}

# Prefetch Settings
Write-Output "[Info]  Checking Prefetch Settings ... "
Write-Output "[Info]  Checking Prefetch Settings ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
$CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current

if (Test-RegistryValue -Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Value "EnablePrefetcher")
{
    $PrefetchParameters = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher).EnablePrefetcher
    if ($PrefetchParameters -match "0")
    {
        Write-Output "[Info]  Prefetching is disabled (0)"
        Write-Output "        Note: The default value is 3."
        Write-Output "[Info]  Prefetching is disabled (0)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        Write-Output "        Note: The default value is 3." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    
    if ($PrefetchParameters -match "1")
    {
        Write-Output "[Info]  Application launch prefetching is enabled (1)"
        Write-Output "        Note: The default value is 3."
        Write-Output "[Info]  Application launch prefetching is enabled (1)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        Write-Output "        Note: The default value is 3." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    
    if ($PrefetchParameters -match "2")
    {
        Write-Output "[Info]  Boot prefetching is enabled (2)"
        Write-Output "        Note: The default value is 3."
        Write-Output "[Info]  Boot prefetching is enabled (2)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        Write-Output "        Note: The default value is 3." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    
    if ($PrefetchParameters -match "3")
    {
        Write-Output "[Info]  Both application launch and boot prefetching is enabled (3)"
        Write-Output "        Note: The default value is 3."

        Write-Output "[Info]  Both application launch and boot prefetching is enabled (3)" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        Write-Output "        Note: The default value is 3." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# Prefetch List
# Win 7 - The Prefetch directory is self cleaning at 128 entries. When the 128 limit is reached Windows will keep the 32 most used Prefetch files.
# Windows 8 and above: Limited to 1024 Prefetch files.
if (Test-Path "$env:SystemDrive\Windows\Prefetch\*.pf")
{
    # Count Prefetch Files
    $Count = (Get-ChildItem -Path "$env:SystemDrive\Windows\Prefetch" -Filter "*.pf" | Measure-Object).Count
    
    # Total Size
    $TotalSize = Get-FileSize((Get-ChildItem -Path "$env:SystemDrive\Windows\Prefetch" -Filter "*.pf" | Measure-Object Length -Sum).Sum)

    Write-Output "[Info]  $Count Prefetch Files found ($TotalSize)."

    # Prefetch Files
    New-Item "$OUTPUT_FOLDER\System-Info\Prefetch" -ItemType Directory -Force | Out-Null

    # TXT
    Get-ChildItem -Path "$env:SystemDrive\Windows\Prefetch" -Filter "*.pf" | Select-Object Name | Out-File "$OUTPUT_FOLDER\System-Info\Prefetch\Prefetch-List.txt"

    # CSV
    Get-ChildItem -Path "$env:SystemDrive\Windows\Prefetch" -Filter "*.pf" | Select-Object Name, Length, @{Name="Size";Expression={ Get-FileSize ($_.Length) }},CreationTime,LastAccessTime,LastWriteTime,CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc | Export-Csv "$OUTPUT_FOLDER\System-Info\Prefetch\Prefetch-List.csv" -NoTypeInformation
}
else
{
    Write-Output "[Info]  No Prefetch Files found."
}

# Roaming User Profiles

# Roaming User Profiles redirects user profiles to a file share so that users receive the same operating system and application settings on multiple computers. 
# When a user signs in to a computer by using an account that is set up with a file share as the profile path, the user's profile is downloaded to the local computer and merged with the local profile (if present).
# When the user signs out of the computer, the local copy of their profile, including any changes, is merged with the server copy of the profile. Typically, a network administrator enables Roaming User Profiles on domain accounts. 

Function Get-RoamingProfile {

Get-WmiObject -Class Win32_UserProfile | Select-Object LocalPath,
    @{N="LastUseTime UTC"; E={$_.ConvertToDateTime($_.LastUseTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}},
    @{N="LastUseTime"; E={$_.ConvertToDateTime($_.LastUseTime).ToString("yyyy-MM-dd HH:mm:ss")}},
    Status,
    @{N="Description"; E={switch($_.Status){
    "0" {'Undefined - The status of the profile is not set.'}
    "1" {'Temporary - The profile is a temporary profile and will be deleted after the user logs off.'}
    "2" {'Roaming - The profile is set to roaming. If this bit is not set, the profile is set to local.'}
    "4" {'Mandatory - The profile is a mandatory profile.'}
    "8" {'Corrupted - The profile is corrupted and is not in use.'}
    }}},
    RemotePath,
    SID
}

New-Item "$OUTPUT_FOLDER\System-Info\Get-RoamingProfile" -ItemType Directory -Force | Out-Null
Get-RoamingProfile | Export-Csv -Delimiter "`t" -Path "$OUTPUT_FOLDER\System-Info\Get-RoamingProfile\RoamingProfile.csv" -NoTypeInformation

# CentralProfile
$SID_LIST = ((Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Force -Exclude 'S-1-5-18', 'S-1-5-19', 'S-1-5-20').Name).split('\')[-1]
$SID_LIST | Out-File "$OUTPUT_FOLDER\System-Info\Get-RoamingProfile\SecurityIdentifer-List.txt"
$Count = ($SID_LIST | Measure-Object).Count
Write-Output "[Info]  $Count Security Identifier (SID) found"
Write-Output "[Info]  $Count Security Identifier (SID) found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

ForEach( $SID in $SID_LIST )
{
    $RID = $SID.split('-')[-1]
    $User = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID").ProfileImagePath).split('\')[2]
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\Get-RoamingProfile\CentralProfile-$RID.txt"

    # Check if CentralProfile value exists
    if (!(Get-Content "$OUTPUT_FOLDER\System-Info\Get-RoamingProfile\CentralProfile-$RID.txt" | Select-String "CentralProfile" -Quiet))
    {
        Write-Output "[Info]  $SID ($User) is a Local User Profile."
        Write-Output "[Info]  $SID ($User) is a Local User Profile." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  $SID ($User) is a Roaming User Profile"
        Write-Output "[Info]  $SID ($User) is a Roaming User Profile" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

#############################################################################################################################################################################################

# Folder Redirection (Current User ONLY)

# Folder Redirection enables users and administrator to redirect the path of a known folder to a new location, manually or by using Group Policy. 
# The new location can be a folder on the local computer or a directory on a file share. Users interact with files in the redirected folder as if it still existed on the local drive. 

# Shell Folders
# In Windows, each user account has associated personal folders, typically known as 'My Documents', 'My Music', and so on. The Windows shell records each user's personal folders, in the following registry keys:
# HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
# HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

# User Shell Folders
# The User Shell Folders subkey stores the paths to Windows Explorer folders for the current user of the computer. 

# Shell Folders vs. User Shell Folders
# The entries can appear in both the older 'Shell Folders' subkey and the 'User Shell Folders' subkey. 

# HKCU vs. HKLM
# The entries can appear in both HKCU and HKLM. The entries that appear in HKCU take precedence over those in HKLM.

Function Get-FolderRedirection {

New-Item "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection" -ItemType Directory -Force | Out-Null

# Shell Folders (HKCU)
if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
{
    (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_Shell-Folders.txt"
}
else
{
    Write-Output '"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" does NOT exist.' | Out-File "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_Shell-Folders.txt"
}

# Check for Network Paths (HKCU)
if (Test-Path "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_Shell-Folders.txt")
{
    if (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_Shell-Folders.txt" | Select-String -Pattern ": \\\\" -Quiet)
    {
        $Count = (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_Shell-Folders.txt" | Select-String -Pattern ": \\\\").Count
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKCU Shell Folders): Network Path"
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKCU Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKCU Shell Folders): Network Path"
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKCU Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# Shell Folders (HKLM)
(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_Shell-Folders.txt"

# Check for Network Paths (HKLM)
if (Test-Path "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_Shell-Folders.txt")
{
    if (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_Shell-Folders.txt" | Select-String -Pattern ": \\\\" -Quiet)
    {
        $Count = (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_Shell-Folders.txt" | Select-String -Pattern ": \\\\").Count
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKLM Shell Folders): Network Path"
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKLM Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKLM Shell Folders): Network Path"
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKLM Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# User Shell Folders (HKCU)
(Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_User-Shell-Folders.txt"

# Check for Network Paths (HKCU)
if (Test-Path "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_User-Shell-Folders.txt")
{
    if (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_User-Shell-Folders.txt" | Select-String -Pattern ": \\\\" -Quiet)
    {
        $Count = (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKCU_User-Shell-Folders.txt" | Select-String -Pattern ": \\\\").Count
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKCU User Shell Folders): Network Path"
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKCU User Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKCU User Shell Folders): Network Path"
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKCU User Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# User Shell Folders (HKLM)
(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_User-Shell-Folders.txt"

# Check for Network Paths (HKLM)
if (Test-Path "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_User-Shell-Folders.txt")
{
    if (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_User-Shell-Folders.txt" | Select-String -Pattern ": \\\\" -Quiet)
    {
        $Count = (Get-Content "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\HKLM_User-Shell-Folders.txt" | Select-String -Pattern ": \\\\").Count
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKLM User Shell Folders): Network Path"
        Write-Output "[Info]  $Count Folder Redirection(s) detected (HKLM User Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
    else
    {
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKLM User Shell Folders): Network Path"
        Write-Output "[Info]  0 Folder Redirection(s) detected (HKLM User Shell Folders): Network Path" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}

# Enumerate Mapped Drives
Get-WmiObject Win32_MappedLogicalDisk | Select-Object Name, ProviderName, VolumeName, FileSystem, @{Name="Total Size (GB)";Expression={"{0:N2}" -F ($_.Size / 1GB)}}, @{Name="Free Space (GB)";Expression={"{0:N2}" -F ($_.FreeSpace / 1GB)}} | Format-Table -AutoSize | Out-File "$OUTPUT_FOLDER\System-Info\Get-FolderRedirection\Mapped-Drives.txt"

}

Get-FolderRedirection

# BitLocker Drive Encryption (BDE)
Write-Output "[Info]  Checking for Encrypted Volumes ..."
Write-Output "[Info]  Checking for Encrypted Volumes ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
New-Item "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes" -ItemType Directory -Force | Out-Null

if (Test-Path "$env:SystemDrive\Windows\System32\manage-bde.exe") 
{
    $BDE = "$env:SystemDrive\Windows\System32\manage-bde.exe"
    & $BDE -protectors -get $env:SystemDrive > "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\Bitlocker-Protectors.txt" 2> $null
    & $BDE -status $env:SystemDrive > "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\Bitlocker-Status.txt" 2> $null

    # BitLocker (SystemDrive)
    # Note: Bitlocker-Status.txt --> System Language
    if ( Get-Content "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\Bitlocker-Status.txt" | Select-String "$env:SystemDrive" | Select-String "Volume" -Quiet )
    {
        if (( Select-String "100 %" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\Bitlocker-Status.txt" -Quiet ) -Or ( Select-String "100,0%" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\Bitlocker-Status.txt" -Quiet ) -Or ( Select-String "100,0 %" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\Bitlocker-Status.txt" -Quiet ))
        {
            Write-Output "[Info]  Detection Method 1: Volume $env:SystemDrive is encrypted using BitLocker."
            Write-Output "[Info]  Detection Method 1: Volume $env:SystemDrive is encrypted using BitLocker." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        }
    }
}

# Magnet Forensics Encrypted Disk Detector (e.g. TrueCrypt, PGP, Bitlocker, SafeBoot, BestCrypt, Check Point, Sophos, or Symantec) --> Doesn't detect BitLocker on AntAnalyzer (XTS-AES 128)
# Note: Encrypted Disk Detector is a command-line tool that can quickly and non-intrusively check for encrypted volumes on a computer system during incident response.
if (Test-Path "$EDD") 
{
    # .NET 4.0 Framework
    if (Test-Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")
    {
        if (!($ProductName -like "*Windows 7*"))
        {
            # EDD
            & $EDD /accepteula /batch > "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" 2> $null
    
            # Encrypted volumes and/or processes were detected by EDD
            if ( Select-String "Encrypted volumes and/or processes were detected by EDD" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" -Quiet )
            {
                Write-Output "[Info]  Encrypted volumes and/or processes were detected by EDD."
                Write-Output "[Info]  Encrypted volumes and/or processes were detected by EDD." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
            else
            {
                Write-Output "[Info]  No encrypted volumes were found by EDD."
                Write-Output "[Info]  No encrypted volumes were found by EDD." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Bitlocker (SystemDrive)
            if (( Select-String "Volume $env:SystemDrive" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" -Quiet ) -And ( Select-String "Bitlocker" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" -Quiet ))
            {
                Write-Output "[Info]  Detection Method 2: Volume $env:SystemDrive is encrypted using BitLocker."
                Write-Output "[Info]  Detection Method 2: Volume $env:SystemDrive is encrypted using BitLocker." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }

            # Bitlocker (SystemVolume)
            if (Select-String "is a Bitlocker encrypted volume" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" -Quiet)
            {
                $EncryptedVolume = (((Get-Content "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" | Select-String "is a Bitlocker encrypted volume") -replace "is a Bitlocker encrypted volume.$", "") -replace "Partition ", "Partition #" | Out-String).Trim()

                # Check if SystemDrive is a Bitlocker encrypted volume
                if (Get-Content "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" | Select-String "$EncryptedVolume" | Select-String "$env:SystemDrive" -Quiet)
                {
                    Write-Output "[Info]  Detection Method 2: Volume $env:SystemDrive is encrypted using BitLocker."
                    Write-Output "[Info]  Detection Method 2: Volume $env:SystemDrive is encrypted using BitLocker." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                }
            }

            # VeraCrypt (Processes)
            if (Select-String "VeraCrypt processes were located" -Path "$OUTPUT_FOLDER\System-Info\Get-EncryptedVolumes\EDD.txt" -Quiet)
            {
                Write-Output "[Info]  VeraCrypt processes were located."
                Write-Output "[Info]  Note: Check 'System-Info\EDD.txt' for further informartion."
                Write-Output "[Info]  VeraCrypt processes were located." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
                Write-Output "[Info]  Note: Check 'System-Info\EDD.txt' for further informartion." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
            }
        }
        else
        {
            Write-Output "[Info]  Magnet Forensics Encrypted Disk Detector will be skipped ..."
            Write-Output "[Info]  Magnet Forensics Encrypted Disk Detector will be skipped ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        }
    }
    else
    {
        Write-Output "[Info]  NET Framework v4 NOT found. Magnet Forensics Encrypted Disk Detector will be skipped ..."
        Write-Output "[Info]  NET Framework v4 NOT found. Magnet Forensics Encrypted Disk Detector will be skipped ..." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
    }
}
else
{
    Write-Output "[Error] EDD.exe NOT found."
    Write-Output "[Error] EDD.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# R&S Trusted Disk
$Service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedDiskService'"
$State = $Service.State
if ($State -eq "Running")
{
    $PathName = ((Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "TrustedDiskService"} | Select-Object PathName).PathName) -replace '"', ""
    $Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($PathName).FileVersion
    Write-Output "[Info]  R&S Trusted Disk ($Version) was found"
    Write-Output "[Info]  R&S Trusted Disk ($Version) was found" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# PhysicalDisk
(Get-WmiObject -Class Win32_DiskDrive | Select-Object DeviceID,Model,SerialNumber,Size,Partitions,MediaType,Description | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\PhysicalDisk.txt" 2> $null

# Windows 10 Class
# https://docs.microsoft.com/en-us/previous-versions/windows/desktop/stormgmt/msft-physicaldisk
$Class = Get-WmiObject -List -Namespace "root\Microsoft\Windows\Storage" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'MSFT_PhysicalDisk' }
if ( $null -ne $Class )
{
    (Get-WmiObject -Class MSFT_PhysicalDisk -Namespace root\Microsoft\Windows\Storage -ErrorAction SilentlyContinue | Select-Object FriendlyName, SerialNumber, MediaType, HealthStatus, LogicalSectorSize, Size, SpindleSpeed | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\MSFT_PhysicalDisk.txt" 2> $null
}

# MediaType
#
# Value Meaning
# 0     Unspecified
# 3     HDD
# 4     SSD
# 5     SCM

# Correlate Physical Device ID to Volume Device ID
$ImageSource = (Get-WmiObject Win32_DiskDrive | ForEach-Object {
  $disk = $_
  $partitions = "ASSOCIATORS OF " +
                "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
  Get-WmiObject -Query $partitions | ForEach-Object {
    $partition = $_
    $drives = "ASSOCIATORS OF " +
              "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
              "WHERE AssocClass = Win32_LogicalDiskToPartition"
    Get-WmiObject -Query $drives | ForEach-Object {
      $driveLetter = $_.DeviceID
      $fltr        = "DriveLetter='$driveLetter'"
      New-Object -Type PSCustomObject -Property @{
        Disk        = $disk.DeviceID
        DriveLetter = $driveLetter
        VolumeName  = $_.VolumeName
        VolumeID    = Get-WmiObject -Class Win32_Volume -Filter $fltr |
                      Select-Object -Expand DeviceID
      }
    }
  }
})

$ImageSource | Out-File "$OUTPUT_FOLDER\System-Info\Source-Drive-Selection.txt"
$ImageSource | Export-Csv "$OUTPUT_FOLDER\System-Info\Source-Drive-Selection.csv" -Delimiter "`t" -NoTypeInformation

# Volume
(Get-WmiObject -Class Win32_Volume | Select-Object DriveLetter,Label,FileSystem,Capacity,FreeSpace,SerialNumber,DeviceID | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\Volume.txt" 2> $null

# LogicalDisk
(Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FreeSpace,Size,VolumeSerialNumber,MediaType,DriveType,FileSystem | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\LogicalDisk.txt" 2> $null

# DiskPartition
(Get-WmiObject -Class Win32_DiskPartition | Select-Object DeviceID,Description,BlockSize,Bootable,Size,StartingOffset | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\DiskPartition.txt" 2> $null

# Shared Folders
(Get-WmiObject -Class Win32_Share | Format-Table Name,Path,Description,Type -AutoSize | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\SharedFolders.txt" 2> $null

# Network Adapter Configuration
(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = "true"' | Select-Object -Property Description, @{name='IPAddress';Expression={($_.IPAddress[0])}}, MacAddress, DHCPEnabled | Out-String).Trim() > "$OUTPUT_FOLDER\System-Info\NetworkAdapterConfiguration.txt" 2> $null
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = "true"' | Select-Object -Property Description, @{name='IPAddress';Expression={($_.IPAddress[0])}}, MacAddress, DHCPEnabled, DefaultIPGateway, @{name='IPSubnet';Expression={($_.IPSubnet[0])}} | Export-Csv "$OUTPUT_FOLDER\System-Info\NetworkAdapterConfiguration.csv" -Delimiter "`t" -NoTypeInformation

# System Environment Variables (set for everyone)
$CurrentControlSet = (Get-ItemProperty "HKLM:\SYSTEM\Select" -Name Current).Current
(Get-ItemProperty "HKLM:\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\System-Environment-Variables.txt"

# User Environment Variables (set for current user)
(Get-ItemProperty "HKCU:\Environment" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\System-Info\User-Environment-Variables_HKCU.txt"

# PCSystemType
$PCSystemType = (Get-Wmiobject -Class Win32_ComputerSystem -ComputerName $env:COMPUTERNAME).PCSystemType

switch($PCSystemType) 
{
    "1" { $EnumPCSystemType = 'Desktop' }
    "2" { $EnumPCSystemType = 'Mobile / Laptop' }
    "3" { $EnumPCSystemType = 'Workstation' }
    "4" { $EnumPCSystemType = 'Enterprise Server' }
    "5" { $EnumPCSystemType = 'Small Office and Home Office (SOHO) Server' }
    "6" { $EnumPCSystemType = 'Appliance PC' }
    "7" { $EnumPCSystemType = 'Performance Server' }
    "8" { $EnumPCSystemType = 'Maximum' }

    default { $EnumPCSystemType = 'PCSystemType is unspecified'}
}

Write-Output "$EnumPCSystemType" | Out-File "$OUTPUT_FOLDER\System-Info\PCSystemType.txt"

# Shadow Copies
if (Get-Command -CommandType Cmdlet Get-CimInstance -ErrorAction SilentlyContinue)
{
    Get-CimInstance Win32_ShadowCopy | Out-File "$OUTPUT_FOLDER\System-Info\ShadowCopies.txt" -Encoding UTF8
    Get-CimInstance Win32_ShadowCopy | ConvertTo-Csv -NoTypeInformation | Out-File "$OUTPUT_FOLDER\System-Info\ShadowCopies.csv" -Encoding UTF8
}

# Plug and Play (PnP) Devices
if (Get-Command -CommandType Function Get-PnpDevice -ErrorAction SilentlyContinue)
{
    Get-PnpDevice | Export-Csv -Path "$OUTPUT_FOLDER\System-Info\Get-PnpDevice.csv" -NoTypeInformation -Encoding UTF8 2> $null
}

# Domain
if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $true)
{
    (Get-WmiObject Win32_ComputerSystem).Domain | Out-File "$OUTPUT_FOLDER\System-Info\Domain.txt" -Encoding UTF8
}

# DomainRole
$DomainRole = (Get-Wmiobject -Class Win32_ComputerSystem -ComputerName $env:COMPUTERNAME).DomainRole

switch($DomainRole) 
{
    "0" { $EnumDomainRole = 'Standalone Workstation' }
    "1" { $EnumDomainRole = 'Member Workstation' }
    "2" { $EnumDomainRole = 'Standalone Server' }
    "3" { $EnumDomainRole = 'Member Server' }
    "4" { $EnumDomainRole = 'Backup Domain Controller' }
    "5" { $EnumDomainRole = 'Primary Domain Controller' }
}

Write-Output "$EnumDomainRole" | Out-File "$OUTPUT_FOLDER\System-Info\DomainRole.txt"

# Enumerate Active SMB Sessions 
if (Get-Command Get-SmbSession -CommandType Function -ErrorAction SilentlyContinue) 
{
    Get-SmbSession | Out-File "$OUTPUT_FOLDER\System-Info\Get-SmbSession.txt" -Encoding UTF8
}

# RDP Sessions
if (Get-Command -CommandType Application qwinsta -ErrorAction SilentlyContinue)
{
    qwinsta /server:localhost > "$OUTPUT_FOLDER\System-Info\RDP-Sessions.txt"
    (qwinsta /server:localhost) -split "\n" -replace '\s\s+', ',' | Out-File "$OUTPUT_FOLDER\System-Info\RDP-Sessions.csv" -Encoding UTF8
}

# IPv4
$IPv4 = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress} | Select-Object -ExpandProperty IPAddress | Where-Object {$_ -notlike "*:*"}
Write-Output "$IPv4" | Out-File "$OUTPUT_FOLDER\System-Info\IPv4.txt" -Encoding UTF8

# IP Address Configuration
if (Get-Command Get-NetIPAddress -CommandType Function -ErrorAction SilentlyContinue) 
{
    Get-NetIPAddress | ConvertTo-Csv -NoTypeInformation | Out-File "$OUTPUT_FOLDER\System-Info\Get-NetIPAddress.csv" -Encoding UTF8
}

# Microsoft Protection Logs
Write-Output "[Info]  Collecting Microsoft Protection Logs (MPLogs) ..."
New-Item "$OUTPUT_FOLDER\System-Info\MPLogs" -ItemType Directory -Force | Out-Null

# MPLogs
if (Test-Path "$env:ALLUSERSPROFILE\Microsoft\Windows Defender\Support\*MPLog-*.log")
{
    Copy-Item "$env:ALLUSERSPROFILE\Microsoft\Windows Defender\Support\*MPLog-*.log" -Destination "$OUTPUT_FOLDER\System-Info\MPLogs"
                
    # Count
    $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\System-Info\MPLogs" -Filter "*MPLog-*.log" | Measure-Object).Count
    Write-Output "[Info]  $Count MPLog(s) found"
}

# MPDetection
if (Test-Path "$env:ALLUSERSPROFILE\Microsoft\Windows Defender\Support\*MPDetection-*.log")
{
    Copy-Item "$env:ALLUSERSPROFILE\Microsoft\Windows Defender\Support\*MPDetection-*.log" -Destination "$OUTPUT_FOLDER\System-Info\MPLogs"
}

# Windows Installer
if (Get-Command -CommandType Cmdlet Get-WinEvent -ErrorAction SilentlyContinue)
{
    # TXT
    Get-WinEvent -ProviderName MsiInstaller | Where-Object Id -eq "1033"  | Select-Object TimeCreated,Message | Format-List * | Out-File "$OUTPUT_FOLDER\System-Info\WindowsInstaller.txt" -Encoding UTF8

    # Custom CSV
    $Installations = Get-WinEvent -ProviderName MsiInstaller | Where-Object Id -eq "1033"
    
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Installation in $Installations)
    {
        $TimeCreated = $Installation | Select-Object -ExpandProperty TimeCreated
        $Message     = $Installation | Select-Object -ExpandProperty Message

        $Line = [PSCustomObject]@{
        "TimeCreated"    = (Get-Date $TimeCreated).ToString("yyyy-MM-dd HH:mm:ss")
        "UserId"         = $Installation.UserId
        "Manufacturer"   = $Message | ForEach-Object{($_ -split ":\s+")[4]} | ForEach-Object{($_ -split "\.\s+")[0]}
        "ProductName"    = $Message | ForEach-Object{($_ -split ":\s+")[1]} | ForEach-Object{($_ -split "\.\s+")[0]}
        "Version"        = $Message | ForEach-Object{($_ -split ":\s+")[2]} | ForEach-Object{($_ -split "\.\s+")[0]}
        "Language"       = $Message | ForEach-Object{($_ -split ":\s+")[3]} | ForEach-Object{($_ -split "\.")[0]}
        "Status"         = $Message | ForEach-Object{($_ -split ":\s+")[5]} | ForEach-Object{($_ -split "\.")[0]}
        "Message"        = $Message
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\System-Info\WindowsInstaller.csv" -NoTypeInformation -Encoding UTF8
}

#endregion SystemInfo

#############################################################################################################################################################################################

#region fsutil

# Check if fsutil exists
if (Get-Command "fsutil" -ErrorAction SilentlyContinue)
{
    # fsutil
    # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil
    New-Item "$OUTPUT_FOLDER\FileSystem\fsutil" -ItemType Directory -Force | Out-Null

    # Drives
    fsutil fsInfo drives > "$OUTPUT_FOLDER\FileSystem\fsutil\Drives.txt" 2> $null

    if ((Test-Path "$OUTPUT_FOLDER\FileSystem\fsutil\Drives.txt") -And ((Get-Item "$OUTPUT_FOLDER\FileSystem\fsutil\Drives.txt").length -gt 0kb))
    {
        (Get-Content "$OUTPUT_FOLDER\FileSystem\fsutil\Drives.txt" | ForEach-Object{($_ -split "\s+")} | Select-String -Pattern ":\\" | ForEach-Object{($_ -replace "\\","")} | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\FileSystem\fsutil\All-Drives.txt"

        $Drives = Get-Content "$OUTPUT_FOLDER\FileSystem\fsutil\All-Drives.txt"

        ForEach( $Drive in $Drives )
        {
            $DriveLetter = "$Drive" | ForEach-Object{($_ -replace ":","")}

            New-Item "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter" -ItemType Directory -Force | Out-Null

            # DriveType
            fsutil fsInfo driveType $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\DriveType.txt" 2> $null

            # Volume Info
            fsutil fsInfo volumeInfo $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\VolumeInfo.txt" 2> $null

            # NTFS Info
            fsutil fsInfo ntfsInfo $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\NTFS-Info.txt" 2> $null

            # Statistics
            fsutil fsInfo statistics $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\Statistics.txt" 2> $null

            # Determining amount of free space on a drive
            fsutil volume diskfree $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\DiskFree.txt" 2> $null

            # allocationreport - Displays information about how storage is used on a given volume
            fsutil volume allocationreport $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\AllocationReport.txt" 2> $null

            # USN Info
            fsutil usn queryjournal $Drive > "$OUTPUT_FOLDER\FileSystem\fsutil\$DriveLetter\USN-Info.txt" 2> $null
        }

        # Cleaning up
        Remove-Item "$OUTPUT_FOLDER\FileSystem\fsutil\All-Drives.txt" -Force
    }

    # TRIM (SSD)
    fsutil behavior query DisableDeleteNotify NTFS > "$OUTPUT_FOLDER\FileSystem\fsutil\SSD-TRIM.txt" 2> $null

    # 0 = TRIM Enabled
    # 1 = TRIM Disabled

    # NTFS Pagefile Encryption --> Encrypting File System (EFS)
    fsutil behavior query encryptpagingfile > "$OUTPUT_FOLDER\FileSystem\fsutil\Pagefile-Encryption.txt" 2> $null
}

#endregion fsutil

#############################################################################################################################################################################################

#region Footer

# Error Log
$Error | Out-File "$OUTPUT_FOLDER\Error.txt"
$Error.Clear()

# Creating Secure Archive
if (Test-Path "$7za") 
{
    if (Test-Path "$OUTPUT_FOLDER") 
    {
        Write-Output "[Info]  Preparing Secure Archive Container [time-consuming task] ... "
        Write-Output "[Info]  Preparing Secure Archive Container [time-consuming task] ... " | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
        & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER.7z" "$OUTPUT_FOLDER\*" > $null 2>&1
                            
        # Archive Size
        $Length = (Get-Item -Path "$OUTPUT_FOLDER.7z").Length
        $Size = Get-FileSize($Length)
        Write-Output "[Info]  Archive Size: $Size"
        Write-Output "[Info]  Archive Size: $Size" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

        # Cleaning up
        if (Test-Path "$OUTPUT_FOLDER")
        {
            Get-ChildItem -Path "$OUTPUT_FOLDER" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$OUTPUT_FOLDER" -Force
        }
    }
}
else
{
    Write-Output "[Error] 7za.exe NOT found."
    Write-Output "[Error] 7za.exe NOT found." | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
}

# Get End Time
$endTime = (Get-Date)
$AcquisitionEndTime = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")

# Echo Time elapsed
Write-Output ""
Write-Output "" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "FINISHED!"
Write-Output "FINISHED!" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall acquisition duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"
Write-Output "$ElapsedTime" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# Acquisition Duration (ISO 8601)
Write-Output "" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "Acquisition Start    : $AcquisitionStartTime UTC" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append
Write-Output "Acquisition Finished : $AcquisitionEndTime UTC" | Out-File "$LOG_DIR\$Timestamp-Logfile.txt" -Append

# MessageBox UI
if ($Pagefile -eq "--Pagefile")
{
    if (Get-Content -Path "$LOG_DIR\$Timestamp-Logfile.txt" | Select-String -Pattern "\[Error\]" -Quiet)
    {
        $ErrorCount = (Get-Content -Path "$LOG_DIR\$Timestamp-Logfile.txt" | Select-String -Pattern "\[Error\]" | Measure-Object).Count
        $MessageBody = "Memory Acquisition completed w/ $ErrorCount error(s).`nPlease check Logfile for further information!"
        $MessageTitle = "Collect-MemoryDump.ps1 (https://lethal-forensics.com/)"
        $ButtonType = "OK"
        $MessageIcon = "Error"
        $Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
    }
    else
    {
        if ($Triage -eq "--Triage")
        {
            # Memory Snapshot + Pagefile Collection (Optional) + Triage Collection (Optional)
            $MessageBody = "Memory Snapshot created successfully.`nPagefile Collection completed.`nTriage Collection completed."
        }
        else
        {
            # Memory Snapshot + Pagefile Collection (Optional)
            $MessageBody = "Memory Snapshot created successfully.`n`nPagefile Collection completed."
        }

        $MessageTitle = "Collect-MemoryDump.ps1 (https://lethal-forensics.com/)"
        $ButtonType = "OK"
        $MessageIcon = "Information"
        $Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
    }
}
else
{
    if (Get-Content -Path "$LOG_DIR\$Timestamp-Logfile.txt" | Select-String -Pattern "\[Error\]" -Quiet)
    {
        $MessageBody = "Memory Acquisition completed with $ErrorCount error(s).`nPlease check Logfile for further information!"
        $MessageTitle = "Collect-MemoryDump.ps1 (https://lethal-forensics.com/)"
        $ButtonType = "OK"
        $MessageIcon = "Error"
        $Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
    }
    else
    {
        if ($Triage -eq "--Triage")
        {
            # Triage Collection (Optional)
            $MessageBody = "Status: Memory Snapshot created successfully.`n`nTriage Collection completed."
        }
        else
        {
            # Memory Snapshot
            $MessageBody = "Status: Memory Snapshot created successfully."
        }
        
        $MessageTitle = "Collect-MemoryDump.ps1 (https://lethal-forensics.com/)"
        $ButtonType = "OK"
        $MessageIcon = "Information"
        $Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
    }
}

if ($Result -eq "OK" ) 
{
    # Set Windows Title back to default
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

    # Exit
    Exit
}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIrxQYJKoZIhvcNAQcCoIIrtjCCK7ICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFKhV4Zpeb7Zuk4Y1Ll35ZmHy
# 8xOggiT/MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG
# 9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t
# 3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiY
# Epc81KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ
# 4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+R
# laOywwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8h
# JiTWw9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw
# 5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrc
# UWhdFczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyY
# Vr15OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIIC
# L9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmww
# fAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# ABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6
# SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3
# w16mNIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9
# XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+
# Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBP
# kKlOtyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHa
# C4ACMRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyP
# DbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDge
# xKG9GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3Gc
# uqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ
# 5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQ
# Yh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bI
# U1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4
# NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW
# 2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZ
# D9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV
# /UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH
# 747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j
# 4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK
# 9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxv
# SK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEE
# ATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBG
# BggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+
# mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFy
# AQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGT
# rQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ
# 9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1D
# GzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCys
# QDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1
# Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSl
# jf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y
# 1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zc
# fF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGt
# aAxOfy/VKNmwuWuAh9kcMIIGXTCCBMWgAwIBAgIQOlJqLITOVeYdZfzMEtjpiTAN
# BgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENB
# IFIzNjAeFw0yNDAxMTUwMDAwMDBaFw0zNTA0MTQyMzU5NTlaMG4xCzAJBgNVBAYT
# AkdCMRMwEQYDVQQIEwpNYW5jaGVzdGVyMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxMDAuBgNVBAMTJ1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgU2lnbmVy
# IFIzNTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAI3RZ/TBSJu9/ThJ
# Ok1hgZvD2NxFpWEENo0GnuOYloD11BlbmKCGtcY0xiMrsN7LlEgcyoshtP3P2J/v
# neZhuiMmspY7hk/Q3l0FPZPBllo9vwT6GpoNnxXLZz7HU2ITBsTNOs9fhbdAWr/M
# m8MNtYov32osvjYYlDNfefnBajrQqSV8Wf5ZvbaY5lZhKqQJUaXxpi4TXZKohLgx
# U7g9RrFd477j7jxilCU2ptz+d1OCzNFAsXgyPEM+NEMPUz2q+ktNlxMZXPF9WLIh
# OhE3E8/oNSJkNTqhcBGsbDI/1qCU9fBhuSojZ0u5/1+IjMG6AINyI6XLxM8OAGQm
# aMB8gs2IZxUTOD7jTFR2HE1xoL7qvSO4+JHtvNceHu//dGeVm5Pdkay3Et+YTt9E
# wAXBsd0PPmC0cuqNJNcOI0XnwjE+2+Zk8bauVz5ir7YHz7mlj5Bmf7W8SJ8jQwO2
# IDoHHFC46ePg+eoNors0QrC0PWnOgDeMkW6gmLBtq3CEOSDU8iNicwNsNb7ABz0W
# 1E3qlSw7jTmNoGCKCgVkLD2FaMs2qAVVOjuUxvmtWMn1pIFVUvZ1yrPIVbYt1aTl
# d2nrmh544Auh3tgggy/WluoLXlHtAJgvFwrVsKXj8ekFt0TmaPL0lHvQEe5jHbuf
# hc05lvCtdwbfBl/2ARSTuy1s8CgFAgMBAAGjggGOMIIBijAfBgNVHSMEGDAWgBRf
# WO1MMXqiYUKNUoC6s2GXGaIymzAdBgNVHQ4EFgQUaO+kMklptlI4HepDOSz0FGqe
# DIUwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQCMEoGA1UdHwRDMEEw
# P6A9oDuGOWh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVT
# dGFtcGluZ0NBUjM2LmNybDB6BggrBgEFBQcBAQRuMGwwRQYIKwYBBQUHMAKGOWh0
# dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ0NB
# UjM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggGBALDcLsn6TzZMii/2yU/V7xhPH58Oxr/+EnrZjpIyvYTz
# 2u/zbL+fzB7lbrPml8ERajOVbudan6x08J1RMXD9hByq+yEfpv1G+z2pmnln5Xuc
# fA9MfzLMrCArNNMbUjVcRcsAr18eeZeloN5V4jwrovDeLOdZl0tB7fOX5F6N2rmX
# aNTuJR8yS2F+EWaL5VVg+RH8FelXtRvVDLJZ5uqSNIckdGa/eUFhtDKTTz9LtOUh
# 46v2JD5Q3nt8mDhAjTKp2fo/KJ6FLWdKAvApGzjpPwDqFeJKf+kJdoBKd2zQuwzk
# 5Wgph9uA46VYK8p/BTJJahKCuGdyKFIFfEfakC4NXa+vwY4IRp49lzQPLo7Wticq
# Maaqb8hE2QmCFIyLOvWIg4837bd+60FcCGbHwmL/g1ObIf0rRS9ceK4DY9rfBnHF
# H2v1d4hRVvZXyCVlrL7ZQuVzjjkLMK9VJlXTVkHpuC8K5S4HHTv2AJx6mOdkMJwS
# 4gLlJ7gXrIVpnxG+aIniGDCCBmswggTToAMCAQICEQCMQZ6TvyvOrIgGKDt2Gb08
# MA0GCSqGSIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBSMzYwHhcNMjQxMTE0MDAwMDAwWhcNMjcxMTE0MjM1OTU5WjBXMQswCQYDVQQG
# EwJERTEWMBQGA1UECAwNTmllZGVyc2FjaHNlbjEXMBUGA1UECgwOTWFydGluIFdp
# bGxpbmcxFzAVBgNVBAMMDk1hcnRpbiBXaWxsaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA0Z9u5pyMwenbCRSzHsUEDUXfGjL+9w05WuvBukPLvldk
# 2NSUP2eI9qAiPQE1tytz+zQD3ZRNEJrXYwtBf++I7H4pf4vC8Mbsk9N+MGm1YmSl
# HKHZirBBYTPWpvFuZFIC7guRSCuMDTquU382HR08ibtXkdl7kg6DKdMIOOZjrhTQ
# W2AfA1QbR8aG71quHgrN5VMV9O8Ed0K9lLW/dsPHlNryq9krPcSIf2LzOFMYAaTt
# SOjvltrQAeZpspyIKAn1+5ruog9wPgIaUPRr9tPRvN8vBT6xSSFlO+003oRK2z42
# dO+MV8K5RJIZxlApNcPiojbWR2kp9F/r54aie6LQcUGUABEpYVl6Qygrp551Z1YM
# L1VrXHAIcWTveXon+lbLP1IQmgWdurM5Z3hrRXkwpSOPpN5qn1rqHbV4x3PKIQHJ
# Vqe11csJYsIQhRLAHBZKZAsor3stLKhH68IjJ0ctXpR9Ut+13EGmr+fm7eCsbSF7
# jlRMd7zPTB3Za2ltMtaJ+RPIuLWoHSOOUx9C1NPNLm3NjCqqumV7aZU7tcHRdgoM
# t4X0ki5CbHEVgKb6bzjulbXOI0xvwDuoqjeTOksHfoONF7bMQQ/4EpPZDKpICdaQ
# 9RqeYJB5z9b3rrfmICfcVnEQySO73IrParF8LVcm3jgoeeq00Lwv03+gSbYonhEC
# AwEAAaOCAbMwggGvMB8GA1UdIwQYMBaAFA8qyyCHKLjsb0iuK1SmKaoXpM0MMB0G
# A1UdDgQWBBSMcmQJhB5e7gHxMGweJ8yPDAgi2zAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzBKBgNVHSAEQzBBMDUGDCsG
# AQQBsjEBAgEDAjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQ
# UzAIBgZngQwBBAEwSQYDVR0fBEIwQDA+oDygOoY4aHR0cDovL2NybC5zZWN0aWdv
# LmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcmwweQYIKwYBBQUH
# AQEEbTBrMEQGCCsGAQUFBzAChjhodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDov
# L29jc3Auc2VjdGlnby5jb20wKAYDVR0RBCEwH4EdbXdpbGxpbmdAbGV0aGFsLWZv
# cmVuc2ljcy5jb20wDQYJKoZIhvcNAQEMBQADggGBAGdHQTDMJblhm/jA9axlmj7W
# l6zWZ5WajmcYG3azCwSgEK9EBnCCwlSGeEmWGnr0+cjEeoxRkgI4GhbZ5PGaW7Rs
# IoP3nfwvw9TXvEmcn33bQC57P+Qh8TJ1PJLO7re3bEesxQ+P25pY7qFKIueVuv11
# P9aa/rakWmRib40iiUAjfTIRQL10qTz6kbI9u83tfimCARdfy9AVtB0tHfWYRklK
# BMKjAy6UH9nqiRcsss1rdtVVYSxepoGdXRObQi2WOxEc8ev4eTexdMN+taIoIszG
# wjHUk9vVznOZgfKugsnuzphHzNowckVmvnHeEcnLDdqdsB0bpKauPIl/rT1Sph8D
# Sn/rqbijw0AHleCe4FArXryLDraMogtvmpoprvNaONuA5fjbAMgi89El7zQIVb7V
# O9x+tYLaD2v0lqLnptkvm86e6Brxj6Kf/ZoeAl5Iui1Xgx94QzPIWbCYPxE6CFog
# 6M03NslqsFeDs8neMeSMfJXJFzIFrslnMZiytUZiqTCCBoIwggRqoAMCAQICEDbC
# sL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNB
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIxMDMyMjAwMDAwMFoXDTM4MDEx
# ODIzNTk1OVowVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBSb290IFI0
# NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIid2LlFZ50d3ei5JoGa
# VFTAfEkFm8xaFQ/ZlBBEtEFAgXcUmanU5HYsyAhTXiDQkiUvpVdYqZ1uYoZEMgtH
# ES1l1Cc6HaqZzEbOOp6YiTx63ywTon434aXVydmhx7Dx4IBrAou7hNGsKioIBPy5
# GMN7KmgYmuu4f92sKKjbxqohUSfjk1mJlAjthgF7Hjx4vvyVDQGsd5KarLW5d73E
# 3ThobSkob2SL48LpUR/O627pDchxll+bTSv1gASn/hp6IuHJorEu6EopoB1CNFp/
# +HpTXeNARXUmdRMKbnXWflq+/g36NJXB35ZvxQw6zid61qmrlD/IbKJA6COw/8lF
# SPQwBP1ityZdwuCysCKZ9ZjczMqbUcLFyq6KdOpuzVDR3ZUwxDKL1wCAxgL2Mpz7
# eZbrb/JWXiOcNzDpQsmwGQ6Stw8tTCqPumhLRPb7YkzM8/6NnWH3T9ClmcGSF22L
# EyJYNWCHrQqYubNeKolzqUbCqhSqmr/UdUeb49zYHr7ALL8bAJyPDmubNqMtuaob
# KASBqP84uhqcRY/pjnYd+V5/dcu9ieERjiRKKsxCG1t6tG9oj7liwPddXEcYGOUi
# WLm742st50jGwTzxbMpepmOP1mLnJskvZaN5e45NuzAHteORlsSuDt5t4BBRCJL+
# 5EZnnw0ezntk9R8QJyAkL6/bAgMBAAGjggEWMIIBEjAfBgNVHSMEGDAWgBRTeb9a
# qitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQU9ndq3T/9ARP/FqFsggIv0Ao9FCUw
# DgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6
# Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9v
# Y3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAA6+ZUHtaES45aHF
# 1BGH5Lc7JYzrftrIF5Ht2PFDxKKFOct/awAEWgHQMVHol9ZLSyd/pYMbaC0IZ+XB
# W9xhdkkmUV/KbUOiL7g98M/yzRyqUOZ1/IY7Ay0YbMniIibJrPcgFp73WDnRDKtV
# utShPSZQZAdtFwXnuiWl8eFARK3PmLqEm9UsVX+55DbVIz33Mbhba0HUTEYv3yJ1
# fwKGxPBsP/MgTECimh7eXomvMm0/GPxX2uhwCcs/YLxDnBdVVlxvDjHjO1cuwbOp
# kiJGHmLXXVNbsdXUC2xBrq9fLrfe8IBsA4hopwsCj8hTuwKXJlSTrZcPRVSccP5i
# 9U28gZ7OMzoJGlxZ5384OKm0r568Mo9TYrqzKeKZgFo0fj2/0iHbj55hc20jfxvK
# 3mQi+H7xpbzxZOFGm/yVQkpo+ffv5gdhp+hv1GDsvJOtJinJmgGbBFZIThbqI+MH
# vAmMmkfb3fTxmSkop2mSJL1Y2x/955S29Gu0gSJIkc3z30vU/iXrMpWx2tS7UVfV
# P+5tKuzGtgkP7d/doqDrLF1u6Ci3TpjAZdeLLlRQZm867eVeXED58LXd1Dk6UvaA
# hvmWYXoiLz4JA5gPBcz7J311uahxCweNxE+xxxR3kT0WKzASo5G/PyDez6NHdIUK
# BeE3jDPs2ACc6CkJ1Sji4PKWVT0/MYIGMDCCBiwCAQEwaTBUMQswCQYDVQQGEwJH
# QjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1
# YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhEAjEGek78rzqyIBig7dhm9PDAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQUjWQw/a2CtX5KN89/O68GOzWTbK8wDQYJKoZIhvcNAQEBBQAE
# ggIAhR/Ugm4EAtHD7RoNFKw5roKd7PgjR5qLXE0YIoMiLSn210IWTg7iqQG9ktGI
# eowI9VJLZAKl0UxvZa+94oEW2wJMupRw737VArxri7cjOdbOdIFXmGSWxheWv/Pk
# ZDUE0CbUygz4wbkv/JzBB5RsSrrcXHNhBEC7mwoMdzoUGMSjB1evRslJ8YVYxh3r
# bx1IAuitj+ZgoNpBrdxB6KsrEf/TyHjy71adU0orqc2L/bbyIHbns6BoVXZ3hCUL
# uf5zhRU5DjG8aca/O2+wX9Dj5413D82aAUIK073A0246NnkGE+DHgUHeAexWB6kr
# vhGboe79hwrAOoRwSJXOIR0oJAkFhjiJIv1/c0HIE8nsp18fKU686w+HBf/DZqJk
# nHOHOw8Ni4l8kTAMzMWhMkXUEEek0N5i5kiI2gjqJQ/DTCgMI9DwTMhcPuvxMsd6
# i8OvX0+vcT+B2/DjpUHH66yg2oz9q1qqaA7tHKHbfV+qBkky4okq5KEBR6A+xQSr
# zrf+N7My/WDGitcHOJI3h8aPnhTpa2ER3Uwy6Ik9YgIAYgxXKlf/lc1fPuCBzjSw
# NbRWTA6YRcoh7vKKtgQqXuXPXFe9ef8MzSG+R6a9MpZ41Z/+oJEp2y3w98Hh+D2D
# 0pj2ZIydJGQMVjAqieNceQlu8HHnZDdCoOxaLqTRdzSnMRqhggMiMIIDHgYJKoZI
# hvcNAQkGMYIDDzCCAwsCAQEwaTBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNgIQOlJqLITOVeYdZfzMEtjpiTANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDMxMDA2
# Mjc1NVowPwYJKoZIhvcNAQkEMTIEMKw0n9/+BtVgsDwQmTwrKrUnZtrD9nB0N8+e
# NcawQkvIASxw4zMYIUn+ksVDtzJqFjANBgkqhkiG9w0BAQEFAASCAgAulmDbvucW
# n/qPQ+3nVlRNTnQS0018aTjVLUG6olzBEDmsaR72HjgbZ+Xu6DoN0PL6pKw4VYff
# pHLdpQxbW+ylTiq2hr8yw1tRm5yOBG4Vep3OF+t19cgvMwCMIU+m3Ub4IxXUqstD
# jO3YUHwFN0KHcvCWdykFkPsBZdZXy6T+e3H3q1XaB6plZkuQ/9/FoobfzbcILO68
# 1QtX/ERRLYHVpK0SR99JlgS8scukLIwWRyoFWt8OgVbvJR8e/VngIhcRnB7cKvJ+
# dlOxfP7OHUJiaWfGCOYLWvKC1YoBdIENh1m1ShB7EKuWtFKUf339G/D63oQ7Q/gY
# VUdJNp8LnG/ei9xQPSLSx9w6Wnz6UTTBmhPmx2hceYX3GLt9Q6uCnfSXR7nf+jDv
# ekdp0Qkfx3fsFrq7BDOspiKFlLC6iab8xbgpYURwdkRdLM7sxA14QoCQbIaZsivM
# XN/II9E5QNldY/BUK0cRouJL8nn2Ati2na8N8yIerqoxtlxW4QoRSzSOiqBBbeJp
# S5MUESGsR6sm10aFoQLyC6/Tt8Ls/l+E3sQxBkPPG4d5yKZKb+kg3VW5KcxFZqgU
# XhKQsdRLee/Ms6wKOLEEi4zBNGXmEu3HzS/5NUdgdEQdo0uZWE9COJm7Q/6GvHhQ
# 9oSMjwsXJhjP+/tmYQKZG0KYgPDNYhIcZQ==
# SIG # End signature block
