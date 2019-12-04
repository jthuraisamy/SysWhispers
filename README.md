# KernelWhispers

Generate header/ASM files for direct system calls.

## Usage and Examples

```
PS C:\Projects\KernelWhispers> py .\kernelwhispers.py --help

usage: kernelwhispers.py [-h] [-p PRESET] [-f FUNCTIONS] [-v VERSIONS] -o OUT_FILE

optional arguments:
  -h, --help            show this help message and exit
  -p PRESET, --preset PRESET
                        Preset ("all", "common")
  -f FUNCTIONS, --functions FUNCTIONS
                        Comma-separated functions
  -v VERSIONS, --versions VERSIONS
                        Comma-separated versions (XP, Vista, 7, 8, 10)
  -o OUT_FILE, --out-file OUT_FILE
                        Output basename (w/o extension)
```

```
PS C:\Projects\KernelWhispers> py .\kernelwhispers.py --preset common --out-file syscalls_common
PS C:\Projects\KernelWhispers> py .\kernelwhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory --out-file syscalls_mem
PS C:\Projects\KernelWhispers> py .\kernelwhispers.py --versions 7,8,10 --out-file syscalls_78X
```

```
PS C:\Projects\KernelWhispers> py .\kernelwhispers.py --preset common --out-file syscom
                           _
  /,  _   ,_   ,__,   _   //     ,_ /_   .  ,   ,_    _   ,_   ,
_/(__(/__/ (__/ / (__(/__(/__/_/_/_/ (__/__/_)__/_)__(/__/ (__/_)_
                                               /
                                              /  @Jackson_T, 2019

KernelWhispers: Generate header/ASM files for direct system calls.

Common functions selected.

Complete! Files written to:
        syscom.asm
        syscom.h
```

## Common/Default Functions

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

## Credits

TBD

## Licence

Apache License, Version 2.0