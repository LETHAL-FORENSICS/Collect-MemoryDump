<p align="center"><a href="https://github.com/PowerShell/PowerShell"><img src="https://img.shields.io/badge/Language-Powershell-blue" style="text-align:center;display:block;"></a> <a href="https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/releases/latest"><img src="https://img.shields.io/github/v/release/LETHAL-FORENSICS/Collect-MemoryDump?label=Release" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Digital%20Signature-Valid-brightgreen" style="text-align:center;display:block;"> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social" style="text-align:center;display:block;"></a></p>

# Collect-MemoryDump
Collect-MemoryDump - Automated Creation of Windows Memory Snapshots for DFIR

Collect-MemoryDump.ps1 is PowerShell script utilized to collect a Memory Snapshot from a live Windows system (incuding Pagefile Collection) in a forensically sound manner.

Features:
* ARM64 Support (MAGNET DumpIt for Windows and MAGNET Response)
* Checks for Hostname and Physical Memory Size before starting memory acquisition
* Checks if you have enough free disk space to save memory dump file
* Collects a Microsoft Crash Dump w/ MAGNET DumpIt for Windows
* Collects a Raw Physical Memory Dump w/ MAGNET DumpIt, MAGNET RAM Capture, Belkasoft Live RAM Capturer and WinPMEM
* Pagefile Collection w/ MAGNET Response &#8594; very useful when dealing with reflective PE injection techniques
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
  
![Help-Message](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/01.jpg)  
**Fig 1:** Help Message  

![AvailableSpace](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/02.jpg)  
**Fig 2:** Check Available Space

![DumpIt - Microsoft Crash Dump](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/03.jpg)  
**Fig 3:** Automated Creation of Windows Memory Snapshot w/ MAGNET DumpIt for Windows (incl. Pagefile)

![DumpIt - Raw Physical Memory Dump](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/04.jpg)  
**Fig 4:** Automated Creation of Windows Memory Snapshot w/ MAGNET DumpIt for Windows (incl. Pagefile)

![WinPMEM](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/05.jpg)  
**Fig 5:** Automated Creation of Windows Memory Snapshot w/ WinPMEM (incl. Pagefile)

![Belkasoft](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/06.jpg)  
**Fig 6:** Automated Creation of Windows Memory Snapshot w/ Belkasoft Live RAM Capturer (incl. Pagefile)

![Pagefile Collection](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/07.jpg)  
**Fig 7:** Pagefile Collection w/ MAGNET Response

![Process-Module Information](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/08.jpg)  
**Fig 8:** Collecting Running Process/Module Information w/ MAGNET Response

![MessageBox](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/09.jpg)  
**Fig 9:** Message Box

![MAGNET RAM Capture GUI](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/10.jpg)  
**Fig 10:** MAGNET RAM Capture

![MAGNET RAM Capture](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/11.jpg)  
**Fig 11:** Automated Creation of Windows Memory Snapshot w/ MAGNET RAM Capture

![MessageBox - Memory Snapshot created successfully](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/12.jpg)  
**Fig 12:** Message Box

![Triage Collection](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/13.jpg)  
**Fig 13:** Triage Collection w/ MAGNET Response

![Full Collection](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/14.jpg)  
**Fig 14:** Windows Memory Snapshot w/ MAGNET DumpIt (incl. Pagefile) + Triage Collection

![MessageBox - Full Collection](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/15.jpg)  
**Fig 15:** Message Box

![SecureArchive](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/16.jpg)  
**Fig 16:** Secure Archive Container (PW: IncidentResponse) and Logfile.txt

![OutputDirectories](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/17.png)  
**Fig 17:** Output Directories

![MemoryDirectories](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/18.png)  
**Fig 18:** Memory Directories (DumpIt and Pagefile)

![Memory](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/19.png)  
**Fig 19:** Memory Snapshot (in a forensically sound manner)

![PageFileInfo](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/20.png)  
**Fig 20:** Pagefile and PageFileInfo

![Pagefile Collection](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/21.png)  
**Fig 21:** Pagefile Collection (in a forensically sound manner)

![SystemInfo](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/22.png)  
**Fig 22:** Collected System Information

![ProcessesAndModules-Extended_Info.tsv](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/23.jpg)  
**Fig 23:** Automated Processing of 'ProcessesAndModules-Extended_Info.tsv' (MAGNET Response)

![ProcessesAndModules-Extended_Info.ps1](https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/6b9d9900266a08b668d385501f0745f330d1d067/Screenshots/24.jpg)  
**Fig 24:** 'ProcessesAndModules-Extended_Info.ps1' &#8594; [MemProcFS-Analyzer](https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer/blob/main/Scripts/ProcessesAndModules-Extended_Info.ps1)

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
