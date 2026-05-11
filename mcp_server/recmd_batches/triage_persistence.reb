Description: SIFT-OWL persistence triage — Run keys, Services, Winlogon, IFEO, AppInit_DLLs
Author: SIFT-OWL
Version: 1.0
Id: 7f4e8901-1ab2-4cde-9876-7e1d0c0a55f1
Keys:
    # HKLM Run keys (SOFTWARE hive)
    -
        Description: HKLM Run
        HiveType: NtUser
        Category: Run keys
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: HKCU Run (per-user autostart)
    -
        Description: HKCU RunOnce
        HiveType: NtUser
        Category: Run keys
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: HKCU RunOnce (delete-on-run autostart)
    -
        Description: HKLM Run
        HiveType: Software
        Category: Run keys
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: HKLM Run (system-wide autostart)
    -
        Description: HKLM RunOnce
        HiveType: Software
        Category: Run keys
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: HKLM RunOnce (delete-on-run system-wide)
    -
        Description: HKLM RunOnceEx
        HiveType: Software
        Category: Run keys
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: HKLM RunOnceEx (legacy)
    -
        Description: Policies Explorer Run
        HiveType: Software
        Category: Run keys
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: Policy-based Run autostart
    # Winlogon
    -
        Description: Winlogon Shell
        HiveType: Software
        Category: Winlogon
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Shell
        Recursive: false
        Comment: Default desktop shell — explorer.exe by default; tamper = T1547.004
    -
        Description: Winlogon Userinit
        HiveType: Software
        Category: Winlogon
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Userinit
        Recursive: false
        Comment: Userinit binary — userinit.exe by default; tamper = T1547.004
    -
        Description: Winlogon Notify packages
        HiveType: Software
        Category: Winlogon
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
        Recursive: true
        Comment: Legacy Winlogon notification packages (XP/2003 era, occasionally abused)
    # IFEO (Image File Execution Options) — T1574.012
    -
        Description: IFEO Debugger
        HiveType: Software
        Category: IFEO
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*
        ValueName: Debugger
        Recursive: true
        Comment: IFEO Debugger value — T1574.012 hijack
    -
        Description: IFEO GlobalFlag
        HiveType: Software
        Category: IFEO
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*
        ValueName: GlobalFlag
        Recursive: true
        Comment: IFEO GlobalFlag (paired with SilentProcessExit MonitorProcess)
    -
        Description: SilentProcessExit
        HiveType: Software
        Category: IFEO
        KeyPath: Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*
        Recursive: true
        Comment: SilentProcessExit MonitorProcess = stealth IFEO variant
    # AppInit_DLLs / AppCertDlls — T1574.001
    -
        Description: AppInit_DLLs
        HiveType: Software
        Category: DLL hijack
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppInit_DLLs
        Recursive: false
        Comment: AppInit_DLLs — every user32-linked process loads these
    -
        Description: AppCertDlls
        HiveType: Software
        Category: DLL hijack
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppCertDlls
        Recursive: false
        Comment: AppCertDlls — CreateProcess interception
    # Services (SYSTEM hive — ControlSet001 by convention)
    -
        Description: Services ImagePath
        HiveType: System
        Category: Services
        KeyPath: ControlSet001\Services\*
        ValueName: ImagePath
        Recursive: true
        Comment: Per-service binary path (T1543.003)
    -
        Description: Services ServiceDll
        HiveType: System
        Category: Services
        KeyPath: ControlSet001\Services\*\Parameters
        ValueName: ServiceDll
        Recursive: true
        Comment: Hosted-service DLL (svchost-driven services)
