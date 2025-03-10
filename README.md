<p align="center"><a href="https://github.com/PowerShell/PowerShell"><img src="https://img.shields.io/badge/Language-Powershell-blue" style="text-align:center;display:block;"></a> <a href="https://github.com/evild3ad/Collect-MemoryDump/releases/latest"><img src="https://img.shields.io/github/v/release/evild3ad/Collect-MemoryDump?label=Release" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Digital%20Signature-Valid-brightgreen" style="text-align:center;display:block;"> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social" style="text-align:center;display:block;"></a></p>

# Collect-MemoryDump
Collect-MemoryDump - Automated Creation of Windows Memory Snapshots for DFIR

Collect-MemoryDump.ps1 is PowerShell script utilized to collect a Memory Snapshot from a live Windows system (incuding Pagefile Collection) in a forensically sound manner.

Features:
* ARM64 Support (MAGNET DumpIt for Windows and MAGNET Response)
* Checks for Hostname and Physical Memory Size before starting memory acquisition
* Checks if you have enough free disk space to save memory dump file
* Collects a Microsoft Crash Dump w/ MAGNET DumpIt for Windows
* Collects a Raw Physical Memory Dump w/ MAGNET DumpIt, MAGNET RAM Capture, Belkasoft Live RAM Capturer and WinPMEM
* Pagefile Collection w/ MAGNET Response (Optional) &#8594; very useful when dealing with reflective PE injection techniques
* Triage-Collection w/ MAGNET Response (Optional)
* Collects Running Process/Module Information w/ MAGNET Response
* Checks for Encrypted Volumes w/ MAGNET Encrypted Disk Detector (EDD)
* Collects BitLocker Recovery Key
* Checks for installed Endpoint Security Tools (AntiVirus and EDR)
* Enumerates all necessary information from the target host to enrich your DFIR workflow
* Creates a password-protected Secure Archive Container (PW: IncidentResponse)

> [!TIP]
> Automated Forensic Analysis of Windows Memory Dumps and corresponding Pagefiles w/ [MemProcFS-Analyzer](https://github.com/evild3ad/MemProcFS-Analyzer)

## First Public Release    
MAGNET Talks - Frankfurt, Germany (July 27, 2022)  
Presentation Title: Modern Digital Forensics and Incident Response Techniques  
https://www.magnetforensics.com/  

## Download  
Download the latest version of **Collect-MemoryDump** from the [Releases](https://github.com/evild3ad/Collect-MemoryDump/releases/latest) section.  

> [!NOTE]
> Collect-MemoryDump does not include all external tools by default.  

You have to download following dependencies:  
* [Belkasoft Live RAM Capturer](https://belkasoft.com/ram-capturer)
* [MAGNET DumpIt for Windows](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)
* [MAGNET Encrypted Disk Detector](https://www.magnetforensics.com/resources/encrypted-disk-detector/)
* [MAGNET RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/)
* [MAGNET Response](https://www.magnetforensics.com/resources/magnet-response/)

Copy the required files to following file locations:

**Belkasoft Live RAM Capturer**  
`$SCRIPT_DIR\Tools\RamCapturer\x64\msvcp110.dll`  
`$SCRIPT_DIR\Tools\RamCapturer\x64\msvcr110.dll`  
`$SCRIPT_DIR\Tools\RamCapturer\x64\RamCapture64.exe`  
`$SCRIPT_DIR\Tools\RamCapturer\x64\RamCaptureDriver64.sys`  
`$SCRIPT_DIR\Tools\RamCapturer\x86\msvcp110.dll`  
`$SCRIPT_DIR\Tools\RamCapturer\x86\msvcr110.dll`  
`$SCRIPT_DIR\Tools\RamCapturer\x86\RamCapture.exe`  
`$SCRIPT_DIR\Tools\RamCapturer\x86\RamCaptureDriver.sys`  
  
**MAGNET DumpIt for Windows**  
`$SCRIPT_DIR\Tools\DumpIt\ARM64\DumpIt.exe`  
`$SCRIPT_DIR\Tools\DumpIt\x64\DumpIt.exe`  
`$SCRIPT_DIR\Tools\DumpIt\x86\DumpIt.exe`  
  
**MAGNET Encrypted Disk Detector**  
`$SCRIPT_DIR\Tools\EDD\EDDv310.exe`  

**MAGNET Ram Capture**  
`$SCRIPT_DIR\Tools\MRC\MRCv120.exe`  

**MAGNET Response**  
`$SCRIPT_DIR\Tools\MagnetRESPONSE\MagnetRESPONSE.exe`  

Check out: [Wiki: How-to-add-or-update-dependencies](https://github.com/evild3ad/Collect-MemoryDump/wiki/How-to-add-or-update-dependencies)

## Usage  
```powershell
.\Collect-MemoryDump.ps1 [-Tool] [--Pagefile] [--Triage]
```

Example 1 - Collect Microsoft Crash Dump and Pagefile  
```powershell
.\Collect-MemoryDump.ps1 -Comae --Pagefile  
```

Example 2 - Collect Raw Physical Memory Dump and Pagefile  
```powershell
.\Collect-MemoryDump.ps1 -DumpIt --Pagefile
```

Example 3 - Collect Raw Physical Memory Dump    
```powershell
.\Collect-MemoryDump.ps1 -WinPMEM  
```

Example 4 - Collect Microsoft Crash Dump, Pagefile and Forensic Artifacts
```powershell
.\Collect-MemoryDump.ps1 -Comae --Pagefile --Triage
```  
</br>

> [!IMPORTANT]  
> Microsoft .NET Framework 4 (or later) must be installed on target system for MAGNET Encrypted Disk Detector and MAGNET Response. Simply skip the Pagefile Collection or download and install Microsoft .NET Framework 4 (Standalone Installer) from the Microsoft download site:  
https://www.microsoft.com/en-us/download/details.aspx?id=17718

> [!IMPORTANT]  
> MAGNET DumpIt for Windows does NOT support Windows 7 target systems. Please use any of the other memory acquisition tools when dealing with Windows 7. 
  
![Help-Message](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/01.png)  
**Fig 1:** Help Message  

![AvailableSpace](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/02.png)  
**Fig 2:** Check Available Space

![DumpIt - Microsoft Crash Dump](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/03.png)  
**Fig 3:** Automated Creation of Windows Memory Snapshot w/ MAGNET DumpIt for Windows (incl. Pagefile)

![DumpIt - Raw Physical Memory Dump](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/04.png)  
**Fig 4:** Automated Creation of Windows Memory Snapshot w/ MAGNET DumpIt for Windows (incl. Pagefile)

![WinPMEM](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/05.png)  
**Fig 5:** Automated Creation of Windows Memory Snapshot w/ WinPMEM (incl. Pagefile)

![Belkasoft](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/06.png)  
**Fig 6:** Automated Creation of Windows Memory Snapshot w/ Belkasoft Live RAM Capturer (incl. Pagefile)

![Pagefile Collection](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/07.png)  
**Fig 7:** Pagefile Collection w/ MAGNET Response

![Process-Module Information](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/08.png)  
**Fig 8:** Collecting Running Process/Module Information w/ MAGNET Response

![MessageBox](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/09.png)  
**Fig 9:** Message Box

![MAGNET RAM Capture GUI](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/10.png)  
**Fig 10:** MAGNET RAM Capture

![MAGNET RAM Capture](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/11.png)  
**Fig 11:** Automated Creation of Windows Memory Snapshot w/ MAGNET RAM Capture

![MessageBox - Memory Snapshot created successfully](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/12.png)  
**Fig 12:** Message Box

![SecureArchive](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/13.png)  
**Fig 13:** Secure Archive Container (PW: IncidentResponse) and Logfile.txt

![OutputDirectories](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/14.png)  
**Fig 14:** Output Directories

![MemoryDirectories](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/15.png)  
**Fig 15:** Memory Directories (DumpIt and Pagefile)

![Memory](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/16.png)  
**Fig 16:** Memory Snapshot (in a forensically sound manner)

![PageFileInfo](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/17.png)  
**Fig 17:** Pagefile and PageFileInfo

![Pagefile Collection](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/18.png)  
**Fig 18:** Pagefile Collection (in a forensically sound manner)

![SystemInfo](https://github.com/evild3ad/Collect-MemoryDump/blob/14fe3946daa65ee553050121d3a5e316236f67d3/Screenshots/19.png)  
**Fig 19:** Collected System Information

## Dependencies  
7-Zip 24.09 Standalone Console (2024-11-29)  
https://www.7-zip.org/download.html  

Belkasoft Live RAM Capturer (2018-10-22)  
https://belkasoft.com/ram-capturer  

MAGNET DumpIt for Windows (2023-01-17) &#8594; Comae-Toolkit-v20230117  
https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/    

MAGNET Encrypted Disk Detector v3.1.0 (2022-06-19)  
https://www.magnetforensics.com/resources/encrypted-disk-detector/     

MAGNET RAM Capture v1.2.0 (2019-07-24)  
https://www.magnetforensics.com/resources/magnet-ram-capture/    

Magnet RESPONSE v1.7.1 (2024-09-07)  
https://www.magnetforensics.com/resources/magnet-response/  

PsLoggedOn v1.35 (2016-06-29)  
https://docs.microsoft.com/de-de/sysinternals/downloads/psloggedon  

WinPMEM 4.0 RC2 (2020-10-13)  
https://github.com/Velocidex/WinPmem/releases  

## Links
[Belkasoft Live RAM Capturer](https://belkasoft.com/ram-capturer)  
[MAGNET DumpIt for Windows](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)  
[MAGNET Encrypted Disk Detector](https://www.magnetforensics.com/resources/encrypted-disk-detector/)  
[MAGNET RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/)  
[MAGNET Response](https://www.magnetforensics.com/resources/magnet-response/)  
[WinPMEM](https://github.com/Velocidex/WinPmem)  
