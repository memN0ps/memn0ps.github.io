---
title: "Process Hollowing"
url: "/Process-Hollowing"
date: 2022-02-23
---

Injecting code into `explorer.exe` or `notepad.exe` is not trivial to evade detection as these processes generally do not generate any network activity. The `svchost.exe` system process is a shared service process that allows several services to share this process to reduce resource consumption, which usually generates network activity. The `svchost.exe` process runs under a SYSTEM integrity level, and that will prevent us from injecting inside it from a lower integrity level. Instead, we could create a process called `svchost.exe` in a `suspended state` and inject it inside this process. Note that we don't have to choose `svchost.exe` to process hollowing successfully.


Once the process is created, we would need to locate the `EntryPoint` of the executable and overwrite its in-memory content with our payload/shellcode and then resume the process and execute our shellcode inside the memory. However, Address Space Layout Randomization (ASLR) makes this procedure tricky. We need to use [ZwQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess) or [NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) to get information about the target process such as the `Process Environment Block (PEB)`, and from the `PEB` we can obtain the image base address of the process and parse the Portable Executable (PE) headers to locate the `EntryPoint` of the executable.

Let's see this in action! :D

## [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)

First, we need to call [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) and pass the path of `svchost.exe` to `lpcommandline`, which is `C:\Windows\System32\svchost.exe`. We will also need to tell this function to start in a suspended state. A suspended process is temporarily turned off and can be restarted in the same state.

### [NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)

We then call [ZwQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess) or [NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) with then pass `ProcessBasicInformation` to the `ProcessInformationClass` to obtain a pointer to the `Process Environment Block (PEB)` structure.

### [Process Environment Block (PEB)](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

The PEB will contain the `ImageBaseAddress` of the newly created process, which can be accessed by adding `PebBaseAddress+0x10`. We can use Windbg to dissect the data structures. Here we can see that the `ImageBaseAddress` is `0x10` bytes away from the `PROCESS_ENVIRONMENT_BLOCK (PEB)` 

```
0:006> dt _PEB
combase!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
   +0x003 IsPackagedProcess : Pos 4, 1 Bit
   +0x003 IsAppContainer   : Pos 5, 1 Bit
   +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
   +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
   +0x004 Padding0         : [4] UChar
   +0x008 Mutant           : Ptr64 Void
   +0x010 ImageBaseAddress : Ptr64 Void
```

We can attach `svchost.exe` to Windbg and dissect these data structures. Here we can see that the `ImageBaseAddress` is `00007ff74d270000`.

```
0:001> !peb
PEB at 000000b56c543000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes
    ImageBaseAddress:         00007ff74d270000
    NtGlobalFlag:             0
    NtGlobalFlag2:            0
    Ldr                       00007ffbafc9a4c0
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 000002b2722048a0 . 000002b272204f00
    Ldr.InLoadOrderModuleList:           000002b272204a10 . 000002b272206eb0
    Ldr.InMemoryOrderModuleList:         000002b272204a20 . 000002b272206ec0
<...snipped...>
```

##  [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)

Since this is a remote process we will need to use [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) to read the `PebBaseAddress+0x10` to give us the `ImageBaseAddress`.


### [IMAGE_DOS_HEADER](https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html)

We can use the `ImageBaseAddress` at  `00007ff74d270000` to dissect the `IMAGE_DOS_HEADER`.

```
0:001> dt _IMAGE_DOS_HEADER 00007ff74d270000
ntdll!_IMAGE_DOS_HEADER
   +0x000 e_magic          : 0x5a4d
   +0x002 e_cblp           : 0x90
   +0x004 e_cp             : 3
   +0x006 e_crlc           : 0
   +0x008 e_cparhdr        : 4
   +0x00a e_minalloc       : 0
   +0x00c e_maxalloc       : 0xffff
   +0x00e e_ss             : 0
   +0x010 e_sp             : 0xb8
   +0x012 e_csum           : 0
   +0x014 e_ip             : 0
   +0x016 e_cs             : 0
   +0x018 e_lfarlc         : 0x40
   +0x01a e_ovno           : 0
   +0x01c e_res            : [4] 0
   +0x024 e_oemid          : 0
   +0x026 e_oeminfo        : 0
   +0x028 e_res2           : [10] 0
   +0x03c e_lfanew         : 0n232
```

Here the `e_lfanew` value is converted to hex.

```
0:001> ?0n232
Evaluate expression: 232 = 00000000`000000e8
```


### [IMAGE_NT_HEADERS](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)

The `ImageBaseAddress + e_lfanew` value should give us the `_IMAGE_NT_HEADERS`. 

```
0:001> dt _IMAGE_NT_HEADERS 00007ff74d270000+0xe8
Symbol _IMAGE_NT_HEADERS not found.
0:001> dt _IMAGE_NT_HEADERS64 00007ff74d270000+0xe8
ntdll!_IMAGE_NT_HEADERS64
   +0x000 Signature        : 0x4550
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER64
```

### [_IMAGE_OPTIONAL_HEADER64](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64)

The `ImageBaseAddress + e_lfanew + OptionalHeader` should give us access to the `_IMAGE_OPTIONAL_HEADER64` which contains the `Relative Virtual Address (RVA)` of the `AddressOfEntryPoint`.

```
0:001> dt _IMAGE_OPTIONAL_HEADER64 00007ff74d270000+0xe8+0x018
ntdll!_IMAGE_OPTIONAL_HEADER64
   +0x000 Magic            : 0x20b
   +0x002 MajorLinkerVersion : 0xe ''
   +0x003 MinorLinkerVersion : 0x14 ''
   +0x004 SizeOfCode       : 0x6600
   +0x008 SizeOfInitializedData : 0x5a00
   +0x00c SizeOfUninitializedData : 0
   +0x010 AddressOfEntryPoint : 0x4e80
   +0x014 BaseOfCode       : 0x1000
   +0x018 ImageBase        : 0x00007ff7`4d270000
   +0x020 SectionAlignment : 0x1000
   +0x024 FileAlignment    : 0x200
   +0x028 MajorOperatingSystemVersion : 0xa
   +0x02a MinorOperatingSystemVersion : 0
   +0x02c MajorImageVersion : 0xa
   +0x02e MinorImageVersion : 0
   +0x030 MajorSubsystemVersion : 0xa
   +0x032 MinorSubsystemVersion : 0
   +0x034 Win32VersionValue : 0
   +0x038 SizeOfImage      : 0x11000
   +0x03c SizeOfHeaders    : 0x400
   +0x040 CheckSum         : 0x1c364
   +0x044 Subsystem        : 2
   +0x046 DllCharacteristics : 0xc160
   +0x048 SizeOfStackReserve : 0x80000
   +0x050 SizeOfStackCommit : 0x4000
   +0x058 SizeOfHeapReserve : 0x100000
   +0x060 SizeOfHeapCommit : 0x1000
   +0x068 LoaderFlags      : 0
   +0x06c NumberOfRvaAndSizes : 0x10
   +0x070 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```

We will need to call [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) again to read the `IMAGE_DOS_HEADER` then obtain the `_IMAGE_NT_HEADERS` and finally obtain `_IMAGE_OPTIONAL_HEADER64` to get the `AddressOfEntryPoint`.

### Virtual Address of EntryPoint

To get access to the Virtual Address of the `EntryPoint` we can add `ImageBaseAddress + AddressOfEntryPoint`. In this example we get the value `00007ff74d274e80` which is the `EntryPoint` for `svchost.exe`.

```
0:001> dd 00007ff74d270000+0x4e80
00007ff7`4d274e80  28ec8348 000087e8 c4834800 ff66e928
00007ff7`4d274e90  ccccffff cccccccc cccccccc cccccccc
00007ff7`4d274ea0  cccccccc 6666cccc 00841f0f 00000000
00007ff7`4d274eb0  890d3b48 75000071 c1c14810 c1f76610
00007ff7`4d274ec0  0175ffff c9c148c3 0162e910 cccc0000
00007ff7`4d274ed0  cccccccc 38ec8348 24648348 33450020
00007ff7`4d274ee0  c03345c9 34d615ff c0330000 38c48348
00007ff7`4d274ef0  ccccccc3 ffcccccc 0034bb25 cccccc00
```

## [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) and [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

We can now use [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to overwrite the original in-memory content with our shellcode and call [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) to resume the execution flow of the program, which will cause it to execute our shellcode.

## PoC

A PoC has been made in Rust using `NTAPI` (`ntdll.dll`) rather than using `winapi` (`kernel32.dll / kernelbase.dll`).

https://github.com/memN0ps/arsenal-rs/tree/main/process_hollowing-rs


## [Detection on Virus Total](https://www.virustotal.com/gui/file/054783446c4e72a1d46b4cca5f57128ad55ebde1511dbdd5f40be6d497644193?nocache=1)

Detection at the time of writing.

![Detection](/Process-Hollowing/detection.png)


## References

* https://memn0ps.github.io/Parallel-Syscalls/
* https://github.com/memN0ps/arsenal-rs/
* https://docs.microsoft.com
* https://en.wikipedia.org/wiki/Svchost.exe
* https://0xrick.github.io/win-internals/pe5/
* https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html