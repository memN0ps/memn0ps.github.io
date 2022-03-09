---
title: "Parallel Syscalls"
url: "/Parallel-Syscalls"
date: 2022-02-12
---

## EDR Parallel-asis through Analysis

Recently MDSec /  [Peter Winter-Smtih](https://twitter.com/peterwintrsmith) researched a new technique and released a blog post [EDR Parallel-asis through Analysis - MDSec](https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/), that show us how to extract system call numbers for 3 critical Windows API functions called `NtOpenFile`, `NtCreateSection` and `NtMapViewOfSection`. Combining these functions allows us to load a fresh copy of `NTDLL.dll` from disk into memory. Before we deep dive into this technique, there are a few fundamental concepts about Windows Internals and Portable Executable (PE) files to learn.

However, if you feel you are already familiar with Windows Internals, PE Files and system calls, then feel free skip to the Parallel-asis technique.

PoCs have been made in various languages: 

* C++: https://github.com/mdsecactivebreach/ParallelSyscalls/
* Rust: https://github.com/memN0ps/arsenal-rs/tree/main/parallel_syscalls-rs
* C#: https://github.com/cube0x0/ParallelSyscalls/
* NIM: https://github.com/frkngksl/ParallelNimcalls


# Windows Internals Fundamentals

## Protection Ring

The Windows operating system has layers of privileges within the architecture known as hierarchical levels or protection rings. Regular applications run in Ring 3, known as user-mode, and privileged services run in Ring 0, Kernel mode. However, applications might need to transition from user-mode to kernel-mode.![1](/Parallel-Syscalls/1.png)
**Credits: [Protection ring - Wikipedia](https://en.wikipedia.org/wiki/Protection_ring)**

## Windows Architecture

High-level diagram view of the Window Architecture:![2](/Parallel-Syscalls/2.png)
**Credits: [Microsoft](https://resources.infosecinstitute.com/topic/windows-architecture-and-userkernel-mode/)**

## What are system calls

A system call or syscall is a mechanism that provides a way to transition from user-mode to kernel-mode. The system call numbers can change between different OS versions or service packs.![3](/Parallel-Syscalls/3.png)
**Credits: [Practical Malware Analysis](https://offensivedefence.co.uk/posts/dinvoke-syscalls/)**

To understand system calls better, we can reverse KERNEL32.DLL, KERNELBASE.DLL and `NTDLL.dll`

Let's take `CreateRemoteThreadEx` as an example. What happens when we call this function under the hood?

Inside WinDbg we can see that `CreateThreadStub` calls `CreateRemoteThreadEx` by dissembling the function inside `KERNEL32.DLL`.

```
0:006> uf KERNEL32!CreateThreadStub
KERNEL32!CreateThreadStub:
00007ffa`7f6eb5a0 4c8bdc          mov     r11,rsp
00007ffa`7f6eb5a3 4883ec48        sub     rsp,48h
00007ffa`7f6eb5a7 448b542470      mov     r10d,dword ptr [rsp+70h]
00007ffa`7f6eb5ac 488b442478      mov     rax,qword ptr [rsp+78h]
00007ffa`7f6eb5b1 4181e204000100  and     r10d,10004h
00007ffa`7f6eb5b8 498943f0        mov     qword ptr [r11-10h],rax
00007ffa`7f6eb5bc 498363e800      and     qword ptr [r11-18h],0
00007ffa`7f6eb5c1 458953e0        mov     dword ptr [r11-20h],r10d
00007ffa`7f6eb5c5 4d894bd8        mov     qword ptr [r11-28h],r9
00007ffa`7f6eb5c9 4d8bc8          mov     r9,r8
00007ffa`7f6eb5cc 4c8bc2          mov     r8,rdx
00007ffa`7f6eb5cf 488bd1          mov     rdx,rcx
00007ffa`7f6eb5d2 4883c9ff        or      rcx,0FFFFFFFFFFFFFFFFh
00007ffa`7f6eb5d6 48ff1573760600  call    qword ptr [KERNEL32!_imp_CreateRemoteThreadEx (00007ffa`7f752c50)]
00007ffa`7f6eb5dd 0f1f440000      nop     dword ptr [rax+rax]
00007ffa`7f6eb5e2 4883c448        add     rsp,48h
00007ffa`7f6eb5e6 c3              ret
```

Searching for the function using IDA Freeware, we can confirm that inside `C:\Windows\System32\kernel.dll`  the function `CreateThreadStub` is calling `CreateRemoteThreadEx` . However, the function `CreateRemoteThreadEx` is not present inside `KERNEL32.DLL`.

![4](/Parallel-Syscalls/4.png)

We can disassemble the `CreateRemoteThreadEx` function inside `KERNELBASE.DLL`. Note that this function is huge and has been omitted for simplicity.

```
0:006> uf KERNELBASE!CreateRemoteThreadEx
KERNELBASE!CreateRemoteThreadEx:
<...ommitted...>
00007ffa`7ddf5535 899424e8000000  mov     dword ptr [rsp+0E8h],edx
00007ffa`7ddf553c 418bc7          mov     eax,r15d
00007ffa`7ddf553f f7d8            neg     eax
00007ffa`7ddf5541 481bc9          sbb     rcx,rcx
00007ffa`7ddf5544 488b842400010000 mov     rax,qword ptr [rsp+100h]
00007ffa`7ddf554c 4823c8          and     rcx,rax
00007ffa`7ddf554f 4585ff          test    r15d,r15d
00007ffa`7ddf5552 490f45c1        cmovne  rax,r9
00007ffa`7ddf5556 4c8d8424e0010000 lea     r8,[rsp+1E0h]
00007ffa`7ddf555e 4c89442450      mov     qword ptr [rsp+50h],r8
00007ffa`7ddf5563 48894c2448      mov     qword ptr [rsp+48h],rcx
00007ffa`7ddf5568 4889442440      mov     qword ptr [rsp+40h],rax
00007ffa`7ddf556d 4c894c2438      mov     qword ptr [rsp+38h],r9
00007ffa`7ddf5572 89542430        mov     dword ptr [rsp+30h],edx
00007ffa`7ddf5576 488b842408010000 mov     rax,qword ptr [rsp+108h]
00007ffa`7ddf557e 4889442428      mov     qword ptr [rsp+28h],rax
00007ffa`7ddf5583 488b842410010000 mov     rax,qword ptr [rsp+110h]
00007ffa`7ddf558b 4889442420      mov     qword ptr [rsp+20h],rax
00007ffa`7ddf5590 4d8bce          mov     r9,r14
00007ffa`7ddf5593 4c8b842418010000 mov     r8,qword ptr [rsp+118h]
00007ffa`7ddf559b baffff1f00      mov     edx,1FFFFFh
00007ffa`7ddf55a0 488d8c24b8000000 lea     rcx,[rsp+0B8h]
00007ffa`7ddf55a8 48ff1599b01800  call    qword ptr [KERNELBASE!_imp_NtCreateThreadEx (00007ffa`7df80648)]
00007ffa`7ddf55af 0f1f440000      nop     dword ptr [rax+rax]
00007ffa`7ddf55b4 8bd8            mov     ebx,eax
00007ffa`7ddf55b6 898424b4000000  mov     dword ptr [rsp+0B4h],eax
00007ffa`7ddf55bd 33f6            xor     esi,esi
00007ffa`7ddf55bf 85c0            test    eax,eax
<...ommitted...>
```

Searching for the `CreateRemoteThreadEx` function inside `C:\Windows\System32\kernelbase.dll` we can see that somewhere inside that function a call to `NtCreateThreadEx` is made.

![5](/Parallel-Syscalls/5.png)

We disassemble `NtCreateThreadEx` function inside `NTDLL.dll`.

```
0:006> uf NTDLL!NtCreateThreadEx
ntdll!NtCreateThreadEx:
00007ffa`805ee570 4c8bd1          mov     r10,rcx
00007ffa`805ee573 b8c1000000      mov     eax,0C1h
00007ffa`805ee578 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffa`805ee580 7503            jne     ntdll!NtCreateThreadEx+0x15 (00007ffa`805ee585)  Branch

ntdll!NtCreateThreadEx+0x12:
00007ffa`805ee582 0f05            syscall
00007ffa`805ee584 c3              ret

ntdll!NtCreateThreadEx+0x15:
00007ffa`805ee585 cd2e            int     2Eh
00007ffa`805ee587 c3              ret
```

Searching for `NtCreateThreadEx` inside `C:\Windows\System32\ntdll.dll`, we see that a system call is made (syscall). In this case, the system call number is `0C1`, but this is Windows version dependent and can change.

![6](/Parallel-Syscalls/6.png)

When the system call is made, a transition from user-mode is made to kernel-mode and `ZwCreateThreadEx` is called that is located inside `C:\Windows\System32\ntoskrnl.exe`. We can confirm this by looking at the system call number `0C1`.

We need to enable kernel debugging to search ntoskrnl.exe via WinDbg. After doing so we can disassemble the `ZwCreateThreadEx` inside `C:\Windows\System32\ntoskrnl.exe`.

```
0: kd> uf nt!ZwCreateThreadEx
nt!ZwCreateThreadEx:
fffff802`783f4ec0 488bc4          mov     rax,rsp
fffff802`783f4ec3 fa              cli
fffff802`783f4ec4 4883ec10        sub     rsp,10h
fffff802`783f4ec8 50              push    rax
fffff802`783f4ec9 9c              pushfq
fffff802`783f4eca 6a10            push    10h
fffff802`783f4ecc 488d053d610000  lea     rax,[nt!KiServiceLinkage (fffff802`783fb010)]
fffff802`783f4ed3 50              push    rax
fffff802`783f4ed4 b8c1000000      mov     eax,0C1h
fffff802`783f4ed9 e962370100      jmp     nt!KiServiceInternal (fffff802`78408640) Branch nt!KiServiceInternal:
fffff802`78408640 4883ec08        sub     rsp,8
fffff802`78408644 55              push    rbp
fffff802`78408645 4881ec58010000  sub     rsp,158h
fffff802`7840864c 488dac2480000000 lea     rbp,[rsp+80h]
fffff802`78408654 48899dc0000000  mov     qword ptr [rbp+0C0h],rbx
fffff802`7840865b 4889bdc8000000  mov     qword ptr [rbp+0C8h],rdi
fffff802`78408662 4889b5d0000000  mov     qword ptr [rbp+0D0h],rsi
fffff802`78408669 fb              sti
fffff802`7840866a 65488b1c2588010000 mov   rbx,qword ptr gs:[188h]
fffff802`78408673 0f0d8b90000000  prefetchw [rbx+90h]
fffff802`7840867a 0fb6bb32020000  movzx   edi,byte ptr [rbx+232h]
fffff802`78408681 40887da8        mov     byte ptr [rbp-58h],dil
fffff802`78408685 c6833202000000  mov     byte ptr [rbx+232h],0
fffff802`7840868c 4c8b9390000000  mov     r10,qword ptr [rbx+90h]
fffff802`78408693 4c8995b8000000  mov     qword ptr [rbp+0B8h],r10
fffff802`7840869a 4c8d1d7f030000  lea     r11,[nt!KiSystemServiceStart (fffff802`78408a20)]
fffff802`784086a1 e85abb6000      call    nt!_guard_retpoline_switchtable_jump_r11 (fffff802`78a14200)
fffff802`784086a6 cc              int     3
fffff802`784086a7 c3              ret
```

We can also view this in IDA and can confirm this by looking at the system call number `0C1`.

We can see that the `KiServiceLinkage` kernel function is called, which is just a small stub that executes the ret instruction immediately. Lastly, the `KiServiceInternal` function is responsible for setting the correct [PreviousMode](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode?redirectedfrom=MSDN), that is used to indicate that a syscall was called by the kernel, and for traversing the Windows system call table, which is also known as System Service Dispatch Table (SSDT).

![7](/Parallel-Syscalls/7.png)

This briefly covers the large topic of Windows Internals but can help us in what we need to do to understand something better within Windows.

# Introduction to Hooking and Unhooking

Hooking is a technique used to manipulate, change, or redirect the program's execution flow to another location in memory. This is something that can be used by malware, AVs and EDRs.

The most common places to hook are in DLLs such as `KERNEL32.dll`, `KERNELBASE.dll` or `NTDLL.dll` as the most crucial Windows API functions are located inside those DLLs.

![hooking_example](/Parallel-Syscalls/hooking_example.png)

**Credits: [Calling CreateRemoteThread via the Windows API](https://kylemistele.medium.com/a-beginners-guide-to-edr-evasion-b98cc076eb9a)**

There are different types of hooking, some of them are listed below:

* `MS Detours`: This is a library provided by Microsoft that allows us to intercept Win32 functions and re-write the Assembly code for the targeted functions.

* `Inline Hooking`: This allows us to replace the targeted function's first few bytes (assembly instructions) with a `jump` instruction to redirect execution flow to another location in memory.

* `Import Address Table (IAT) Hooking`: The Import Address table is a lookup table of function pointers for functions imported from DLLs or executables. IAT hooking allows us to replace the function address in the Import Address Table with another to redirect the program's execution flow.

## Unhooking

The majority of the EDRs have started to hook things, so why don't we unhook them? Well, we totally can. However, the problem with hooking is that you will still need to use hooked Win32 API functions to do the unhooking business, which may cause the EDR to flag you.

The [@therealwover](https://twitter.com/TheRealWover) has explained some cool bypassing techniques in [Emulating Covert Operations - Dynamic Invocation (Avoiding PInvoke & API Hooks) – The Wover – Red Teaming, .NET, and random computing topics](https://thewover.github.io/Dynamic-Invoke/)

For example:

"DInvoke provides you with many options for how to execute unmanaged code."

* "Want to bypass IAT Hooking for a suspicious function? No problem! Just use GetLibraryAddress or GetExportAdress to find the function by parsing the module’s EAT."

* "Want to avoid calling LoadLibrary and GetProcAddress? Use GetPebLdrModuleEntry to find the module by searching the PEB."
- "Want to avoid inline hooking? Manually map a fresh copy of the module and use it without any userland hooks in place."

- "Want to bypass all userland hooking without leaving a PE suspiciously floating in memory? Go native and use a syscall!"

More information about hooking, unhooking, system calls and more (exercise for the reader):

* https://thewover.github.io/Dynamic-Invoke/
- https://guidedhacking.com/threads/how-to-hook-functions-code-detouring-guide.14185/

- https://www.mdsec.co.uk/2020/08/firewalker-a-new-approach-to-generically-bypass-user-space-edr-hooking/

- https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa

- https://jhalon.github.io/utilizing-syscalls-in-csharp-1/

- https://jhalon.github.io/utilizing-syscalls-in-csharp-2/

- https://blog.nviso.eu/2021/10/21/kernel-karnage-part-1/

- https://jmpesp.me/malware-analysis-syscalls-example/

- https://github.com/Mr-Un1k0d3r/EDRs

## System Calls Directly

Rather than calling the functions directly from `KERNEL32.dll` or `NTDLL.dll`, you might think, can't we use the system call numbers directly? Yes, sure you can. However,  as we have seen earlier, the system call number is different for each function and can change between OS and service pack versions. So probably not a good idea to hard code the system call number.

The Assembly code snippet below shows what the system call number for the `ntdll!NtOpenProcess` functions looks like for the present version of Windows. The Assembly code is usually the same for all functions, but the number `26` will be replaced with another, depending on the function, OS and service pack.

```cpp
mov r10,rcx             // 0x4c 0x8b 0xd1
mov eax, 26h            // 0xb8 xyz xyz 0x00 0x00
syscall                 // 0x0f 0x05   
ret                     // 0xc3
```

Another problem would be to get the system call number at run time of the program. To get the system call number at run time, we will have to do the following:

- Get the base address of `NTDLL.dll` using [GetModuleHandleA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea), which retrieves a module handle for the specified module. Although this can be hooked, we would want to avoid using this.
- Go through the Export Address Table (EAT) of the `NTDLL.dll` to get the address of the functions we need.
- Extract the system call numbers from the address of the function.
- Perform the system call.

So how do we emulate `GetModuleHandleA` function? Keep reading for the answer.


# Introduction to the Thread Environment Block (TEB) / Process Environment Block (PEB)

Each process has a `Thread Environment block (TEB)` and inside the TEB we can find the `Process Environment Block (PEB)`. ["The Thread Environment Block (TEB structure) describes the state of a thread."](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)

```cpp
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```

Inside the PEB we have a data structure called `_PEB_LDR_DATA`: ["Contains information about the loaded modules for the process."](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

Inside the `_PEB_LDR_DATA` data structure we have something called `InMemoryOrderModuleList` which is: ["The head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an LDR_DATA_TABLE_ENTRY structure. For more information, see Remarks."](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)

```cpp
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

["A **LIST_ENTRY** structure describes an entry in a doubly linked list or serves as the header for such a list."](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry)

Inside `InMemoryOrderModuleList LIST_ENTRY`, we have `FLINK` and `BLINK`. The `FLINK` member points to the next entry in the `InMemoryOrderModuleList`, and the `BLINK` member points to the previous entry in the `InMemoryOrderModuleList`.

```cpp
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;
```

Why is this important to us? `_TEB -> _PEB -> _PEB_LDR_DATA -> InMemoryOrderModuleList` is important to us because it contains a list that includes the loaded modules for the process. When we access `InMemoryOrderModuleList.FLINK`, it will point towards the `_LDR_DATA_TABLE_ENTRY` data structure and contain information about the first loaded module in the process.

The `LDR_DATA_TABLE_ENTRY` structure is defined as follows:

```cpp
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

To sum this up, if we want to get the base address of a module (dll) inside a process. We need to go through `_TEB  -> _PEB ->  _PEB_LDR_DATA -> InMemoryOrderModuleList.FLINK -> _LDR_DATA_TABLE_ENTRY -> DllBase`

Here is an excellent diagram that shows what I've explained above. However, `NTDLL.dll` may not be the first module in the list:

![PE Structure](/Parallel-Syscalls/peb.png)

**Credits [Module Base](https://mohamed-fakroud.gitbook.io/red-teamings-dojo/shellcoding/leveraging-from-pe-parsing-technique-to-write-x86-shellcode)**


# Introduction to Portable Executable Files

The data structures we will talk about are essential for us and will become apparent later in this post.

Here are two diagrams of what we are about to discuss (Portable Executable File Structure):

![PE Structure](/Parallel-Syscalls/PE-Structure.png)
**Credits: [PE Structure](https://tech-zealots.com/wp-content/uploads/2018/05/PE-Structure.png)**


![4](/Parallel-Syscalls/pe_file.png)

**Credits: [PE Structure](https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/)**



### [_IMAGE_DOS_HEADER](https://0xrick.github.io/win-internals/pe3/)

Every Portable Executable (PE) file starts with a small MS-DOS executable that was required in the early days of Windows and this small stub executable would, at a minimum, display a message saying that Windows was required to run the application. The default error message is “This program cannot be run in DOS mode.”
The first bytes of the Portable Executable (PE) file are, the traditional MS-DOS header, also called the IMAGE_DOS_HEADER structure.


There are two important values in this header. The first is the `e_magic` variable of type `WORD (16-bit)` value, that must be `0x5A4D`. This value is `“MZ”` in ASCII which is the initials of Mark Zbikowski.
The second value is `e_lfanew` at offset `3CH` that contains the file offset of the start of the Portable Executable (PE) file which is also called `IMAGE_NT_HEADERS` structure.


```cpp
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

### [_IMAGE_NT_HEADERS](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)


The Portable Executable Header is a structure of structures that is formed by combining together a few other structures. The signature of the `IMAGE_NT_HEADERS` is `50450000h (“PE\0\0” in ASCII)`. The `IMAGE_OPTIONAL_HEADER` is important to us in this case. See MSDN documentation for more information about structures not explained in this post.


```cpp
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;


typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```


### [_IMAGE_OPTIONAL_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)


The `_IMAGE_OPTIONAL_HEADER` structure contains important information such as `AddressOfEntryPoint` which holds the Relative Virtual Address (RVA) of the EntryPoint (EP) for the module. This structure also has the `Magic (WORD)` member which defines if the module is 32 or 64-bit. A Relative Virtual Address (RVA) is the virtual address minus the base address of a file image, once an object from the file is loaded in memory.

The `BaseOfCode` and `BaseOfData` members hold the Relative Virtual Address (RVA) of the starting of the `.code` and `.data` sections.

The `ImageBase` member contains the base address of the module which is the preferred `Virtual Address (VA)` of where the Portable Executable (PE) file will be loaded in memory. The Virtual Address (VA) by default is `0x00400000` for applications and `0x10000000` for DLLs.

The most important member for us in this scenario is the `DataDirectory` array member that is a pointer to the first `IMAGE_DATA_DIRECTORY` structure. For example, the index number of the desired directory entry can be: `IMAGE_DIRECTORY_ENTRY_EXPORT (index 0)` which is the export directory or `IMAGE_DIRECTORY_ENTRY_IAT (index 12)`, which is `Import address table (IAT)` etc... More information on MSDN documentation.


```cpp
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

### [_IMAGE_DATA_DIRECTORY](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)


Each `_IMAGE_DATA_DIRECTORY_STRUCTURE` (16 by default), contains the members `VirtualAddress (DWORD)` and `Size (DWORD)`, which is Relative Virtual Address (RVA) and size of the data inside the Portable Executable (PE) Image at runtime.

A few important examples would be `ExportTableAddress` that has the table of exported functions, `ImportTableAddress` which has table of imported functions, `ResourceTable` that has the table of resources like images embedded in the PE file and `ImportAddressTable (IAT)` which contains the addresses of the imported functions at runtime.


```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```


### [_IMAGE_SECTION_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)


The section table is an array of `_IMAGE_SECTION_HEADER` structures and each structure will contain information about its associated section, such as address, size and characteristics that describe the access permissions inside that section. The section name can be at most 8 ASCII chars long which means that this member will always take up 8 bytes of memory.

Types:
* `.text / code` – Normally the first section that contains executable code for the application and the entry point. Also is generally read-only.

* `.data` - This will contain initialized data for the application such as strings, global variable and local static variable.

* `.bss` - This contains uninitialized static and global variables.
`.rdata or .idata` - This is usually where the import address table is located, which is the table that lists the Win32 APIs such as names and associated DLLs used by the application.

* `.rsrc` - Contains resources for the module such as images used for the application User Interface.

* `.reloc` - Hold the entries for all base relocations in the image. The Base Relocation Table field in the optional header data directories gives the number of bytes in the base relocation table.

This is a non-exhausted list and does not always imply that they will be used for the same purpose or have the same name as it can be changed by the author.



```
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

### [_IMAGE_EXPORT_DIRECTORY](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/)


Once we have the DLL base address we can need to parse the `_IMAGE_EXPORT_DIRECTORY` data structure that contains important information, such as function addresses and function names. ["The export symbol information begins with the export directory table, which describes the remainder of the export symbol information. The export directory table contains address information that is used to resolve imports to the entry points within this image."](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)

```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {              
    DWORD   Characteristics;            
    DWORD   TimeDateStamp;                
    WORD    MajorVersion;             
    WORD    MinorVersion;             
    DWORD   Name;                   // The name of the Dll
    DWORD   Base;                   // Number to add to the values found in AddressOfNameOrdinals to retrieve the "real" Ordinal number of the function (by real I mean used to call it by ordinals).
    DWORD   NumberOfFunctions;      // Number of all exported functions      
    DWORD   NumberOfNames;          // Number of functions exported by name      
    DWORD   AddressOfFunctions;     // Export Address Table. Address of the functions addresses array.   
    DWORD   AddressOfNames;         // Export Name table. Address of the functions names array.        
    DWORD   AddressOfNameOrdinals;  // Export sequence number table.  Address of the Ordinals (minus the value of Base) array.             
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;    
```

**Credits: [_IMAGE_EXPORT_DIRECTORY](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/)**

Here is an excellent image that shows an overview of what we have talked about above.

![PE Structures](/Parallel-Syscalls/pe_diagram.jpg)

**Credits: [Overview of the PE Headers](https://secureyourit.co.uk/wp/2020/04/12/walking-the-peb-with-vba-x64/)**

There are 3 things we are intersted in here, the `AddressOfFunctions`, `AddressOfNames` and `AddressOfNameOrdinals`arrays.

Each index in the array contains a unique entry linked with each other. For example, if we decided to loop through `AddressOfNames` by the length of `NumberOfNames` and we find the function we are looking for, such as `NtCreateRemoteThread` then we can access the function's address by indexing the `AddressOfNameOrdinals` array in the same iteration of the loop which will hold the index of the corresponding address of the function in the `AddressOfFunctions` array.

For example, if the `AddressOfNames[name4]` contains the function name we want then we can access the `AddressOfNameOrdinals[8]` (same index `AddressOfNames`) which will hold the index of the of the function in the `AddressOfFunctions` array and that index in `AddressOfFunctions` could be `AddressOfFunctions[address8]` as shown in the diagram. Although, the address we will get is called the `Relative Virtual Address (RVA)`, which is the virtual address of an object not including the image base address. To get the real address of the function in memory, we have to add the image base address with `Relative Virtual Address (RVA)`.

![EAT](/Parallel-Syscalls/eat.png)

**Credits: [Export Directory](https://resources.infosecinstitute.com/topic/the-export-directory/)**


To sum this up, if we want to get the base address of a module (dll) inside a process, we need to go through: `_TEB -> _PEB -> _PEB_LDR_DATA -> InMemoryOrderModuleList.FLINK -> _LDR_DATA_TABLE_ENTRY -> DllBase`. 

To get the addresses of functions within that module we need to go through the PE headers: 
`_IMAGE_DOS_HEADER.e_lfanew -> _IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress -> _IMAGE_EXPORT_DIRECTORY.AddressOfNames` or `_IMAGE_EXPORT_DIRECTORY.AddressOfFunctions` or `_IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals`.



More information about Portable Executable File and Export Directory Table (exercise for the reader):

- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

- https://0xrick.github.io/win-internals/pe5/

- https://0xevilc0de.com/locating-dll-name-from-the-process-environment-block-peb/

- https://resources.infosecinstitute.com/topic/the-export-directory/

- https://blogs.keysight.com/blogs/tech/nwvs.entry.html/2020/07/27/debugging_malwarewi-hk5u.html

- https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/

- https://mohamed-fakroud.gitbook.io/red-teamings-dojo/shellcoding/leveraging-from-pe-parsing-technique-to-write-x86-shellcode

- https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/

## Parallel-asis

Enough of this madness! Let's get down to real business. Please note that this is an oversimplification of the technique, and MDSec has done a much better job explaining it.

Microsoft has implemented Parallel DLL loading from the starting of Windows 10, which allows loading DLLs recursively in parallel rather than synchronously running single-threaded. To increase performance on Windows 10 upon process initialization, a pool of worker threads are created, and the parent process defines the number of threads. The master thread is referred to as `ntdll!LdrInitializeThunk`, and any other threads in the thread pool created by the master are called a worker threads.

```
0:008> u ntdll!LdrInitializeThunk
ntdll!LdrInitializeThunk:
00007ffc`6477a8b0 4053            push    rbx
00007ffc`6477a8b2 4883ec20        sub     rsp,20h
00007ffc`6477a8b6 488bd9          mov     rbx,rcx
00007ffc`6477a8b9 e81a000000      call    ntdll!LdrpInitialize (00007ffc`6477a8d8)
00007ffc`6477a8be b201            mov     dl,1
00007ffc`6477a8c0 488bcb          mov     rcx,rbx
00007ffc`6477a8c3 e8d8960200      call    ntdll!NtContinue (00007ffc`647a3fa0)
00007ffc`6477a8c8 8bc8            mov     ecx,eax
```

What is of interest to us attackers is that to mitigate parallel loading hazards such as corrupt memory or compatibility, Windows will try and see if a process is hooked before enabling parallel loading by getting `ntdll!LdrpEnableParallelLoading` to call `ntdll!LdrpDetectDetour` and if a hook is detected, then function `ntdll!LdrpDetectDetour` is set to true and the thread pool is drained and released.

```
0:008> u ntdll!LdrpEnableParallelLoading
ntdll!LdrpEnableParallelLoading:
00007ffc`64773b60 48895c2408      mov     qword ptr [rsp+8],rbx
00007ffc`64773b65 57              push    rdi
00007ffc`64773b66 4883ec70        sub     rsp,70h
00007ffc`64773b6a 8bf9            mov     edi,ecx
00007ffc`64773b6c e8ab090000      call    ntdll!LdrpDetectDetour (00007ffc`6477451c)
00007ffc`64773b71 85ff            test    edi,edi
00007ffc`64773b73 0f8503850500    jne     ntdll!LdrpEnableParallelLoading+0x5851c (00007ffc`647cc07c)
00007ffc`64773b79 e872c6fdff      call    ntdll!RtlGetSuiteMask (00007ffc`647501f0)

0:008> u ntdll!LdrpDetectDetour
ntdll!LdrpDetectDetour:
00007ffc`6477451c 4057            push    rdi
00007ffc`6477451e 4883ec30        sub     rsp,30h
00007ffc`64774522 803d375b100000  cmp     byte ptr [ntdll!LdrpDetourExist (00007ffc`6487a060)],0
00007ffc`64774529 757f            jne     ntdll!LdrpDetectDetour+0x8e (00007ffc`647745aa)
00007ffc`6477452b 33d2            xor     edx,edx
00007ffc`6477452d 488d0d0c661000  lea     rcx,[ntdll!LdrpThunkSignature (00007ffc`6487ab40)]
00007ffc`64774534 4c8d054d8d0b00  lea     r8,[ntdll!LdrpCriticalLoaderFunctions (00007ffc`6482d288)]
00007ffc`6477453b 8d7a01          lea     edi,[rdx+1]
```

But how is this important to us attackers again? Well, the process of when and how the hooks are examined are essential to us, which is defined in `ntdll!LdrpCriticalLoaderFunctions`. 


The first 16 bytes of the following functions are examined to see if they have been modified by comparing against the known good bytes in the `ntdll!LdrpThunkSignature` array, which is stored in the `.data` section of`NTDLL.dll`. However, the `ntdll!LdrpThunkSignature` array is not initialised until `NTDLL.dll` is mapped in the process.

* ntdll!NtOpenFile
* ntdll!NtCreateSection
* ntdll!ZqQueryAttributes
* ntdll!NtOpenSection
* ntdll!ZwMapViewOfSection

```
0:008> u ntdll!LdrpCriticalLoaderFunctions
ntdll!LdrpCriticalLoaderFunctions:
00007ffc`6482d288 a03d7a64fc7f000080 mov   al,byte ptr [8000007FFC647A3Dh]
00007ffc`6482d291 407a64          jp      ntdll!RtlpMemoryZoneCriticalRoutines+0x48 (00007ffc`6482d2f8)
00007ffc`6482d294 fc              cld
00007ffc`6482d295 7f00            jg      ntdll!LdrpCriticalLoaderFunctions+0xf (00007ffc`6482d297)
00007ffc`6482d297 00e0            add     al,ah
00007ffc`6482d299 3e7a64          ht jp   ntdll!RtlpMemoryZoneCriticalRoutines+0x50 (00007ffc`6482d300)
00007ffc`6482d29c fc              cld
00007ffc`6482d29d 7f00            jg      ntdll!LdrpCriticalLoaderFunctions+0x17 (00007ffc`6482d29f)
```

This should immediately ring a bell for us attackers. If not, then don't worry, but the question that comes to mind is that why are the first 16 bytes of those critical functions compared with `ntdll!LdrpThunkSignature` and how? Does that mean that `ntdll!LdrpThunkSignature` array will have the system call numbers for `ntdll!NtOpenFile`, `ntdll!NtCreateSection` and `ntdll!NtMapViewOfSection`? What can we do with those functions or have been doing in the past ;) ?

Let's take a look then :)

W00TW00T! Would you look at that! Looking at `LdrpThunkSignature` shows that it hold 3 system call numbers.

```
ntdll!LdrpThunkSignature:
00007ffc`6487ab40 4c8bd1          mov     r10,rcx
00007ffc`6487ab43 b833000000      mov     eax,33h
00007ffc`6487ab48 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffc`6487ab50 4c8bd1          mov     r10,rcx
00007ffc`6487ab53 b84a000000      mov     eax,4Ah
00007ffc`6487ab58 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffc`6487ab60 4c8bd1          mov     r10,rcx
00007ffc`6487ab63 b83d000000      mov     eax,3Dh
```

At the time of the blog the system call numbers `0x33`, `0x4a` and `0x3D` are for `ntdll!NtOpenFile`, `ntdll!NtCreateSection` and `ntdll!NtMapViewOfSection`. We can double check using WinDbg.

```
0:008> u ntdll!NtOpenFile
ntdll!NtOpenFile:
00007ffc`647a3da0 4c8bd1          mov     r10,rcx
00007ffc`647a3da3 b833000000      mov     eax,33h
00007ffc`647a3da8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffc`647a3db0 7503            jne     ntdll!NtOpenFile+0x15 (00007ffc`647a3db5)
00007ffc`647a3db2 0f05            syscall
00007ffc`647a3db4 c3              ret
00007ffc`647a3db5 cd2e            int     2Eh
00007ffc`647a3db7 c3              ret
```

```
0:008> u ntdll!NtCreateSection
ntdll!NtCreateSection:
00007ffc`647a4080 4c8bd1          mov     r10,rcx
00007ffc`647a4083 b84a000000      mov     eax,4Ah
00007ffc`647a4088 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffc`647a4090 7503            jne     ntdll!NtCreateSection+0x15 (00007ffc`647a4095)
00007ffc`647a4092 0f05            syscall
00007ffc`647a4094 c3              ret
00007ffc`647a4095 cd2e            int     2Eh
00007ffc`647a4097 c3              ret
```

```
0:008> u ntdll!NtMapViewOfSection
ntdll!NtMapViewOfSection:
00007ffc`647a3c40 4c8bd1          mov     r10,rcx
00007ffc`647a3c43 b828000000      mov     eax,28h
00007ffc`647a3c48 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffc`647a3c50 7503            jne     ntdll!NtMapViewOfSection+0x15 (00007ffc`647a3c55)
00007ffc`647a3c52 0f05            syscall
00007ffc`647a3c54 c3              ret
00007ffc`647a3c55 cd2e            int     2Eh
00007ffc`647a3c57 c3              ret
```

Yaaaaay! The system call numbers match.

1. The functions `ntdll!NtOpenFile`, `ntdll!NtCreateSection` and `ntdll!NtMapViewOfSection` will allow us to load a fresh unhooked copy of NTDLL into memory.
2. Once we have loaded NTDLL in memory, we can parse the Export Address Table (EAT) and obtain the address of any function we like, as explained before.
3. Once we have the address of the functions we need, we can extract the system call number at run time and call the functions we need to do the magic we need xD.

More information: (reading exercise for the user):

* https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/
* https://blogs.blackberry.com/en/2017/10/windows-10-parallel-loading-breakdown.
* https://stackoverflow.com/questions/42789199/why-there-are-three-unexpected-worker-threads-when-a-win32-console-application-s


# Rust

I've ported the code to Rust, which can be tuned to make a library for system calls.

https://github.com/memN0ps/arsenal-rs/tree/main/parallel_syscalls-rs

## Why Rust?

Why not? Rust is awesome! A low-level statically (compiled) and strongly typed systems programming language that is faster than C/C++, allowing you to achieve memory safety, concurrency and perform low-level tasks writing high-level code with an excellent compiler, community and documentation. I have moved away from my old favourite languages C/C++/C#, and started my new Rusty adventure.

This project has allowed me to learn about Rust Windows Internals and enhance my red teaming skills. I'm relatively new to Rust, but I firmly believe Rust is the future for robust programs, red teaming and malware development.

Read more about Rust here:

* https://kerkour.com/why-rust-for-offensive-security/
* https://zerotomastery.io/blog/why-you-should-learn-rust/
* https://github.com/skerkour/black-hat-rust
* https://github.com/trickster0/OffensiveRust
* https://github.com/Kudaes/DInvoke_rs
* https://github.com/zorftw/kdmapper-rs
* https://github.com/postrequest/link
* https://github.com/kmanc/remote_code_oxidation


Sorry for the typos and grammar mistakes in advance. It takes a lot of effort to write a blog, it is easy to get lazy.

Sorry if I missed anyone for the credits. Thanks for reading. All credits to [MDsec](https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/) and most of all [Peter Winter-Smith](https://twitter.com/peterwintrsmith).

## References

* https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/
* https://twitter.com/peterwintrsmith
* https://offensivedefence.co.uk/posts/dinvoke-syscalls/
* https://thewover.github.io/Dynamic-Invoke/
* https://en.wikipedia.org/wiki/Protection_ring
* https://www.codereversing.com/blog/archives/128
* https://secureyourit.co.uk/wp/2020/04/12/walking-the-peb-with-vba-x64/
* https://research.nccgroup.com/2020/05/25/cve-2018-8611-exploiting-windows-ktm-part-5-5-vulnerability-detection-and-a-better-read-write-primitive/
* https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
* https://blogs.blackberry.com/en/2017/10/windows-10-parallel-loading-breakdown
* https://resources.infosecinstitute.com/topic/windows-architecture-and-userkernel-mode/
* https://kylemistele.medium.com/a-beginners-guide-to-edr-evasion-b98cc076eb9a
* https://resources.infosecinstitute.com/topic/the-export-directory/
* https://guidedhacking.com/threads/how-to-hook-functions-code-detouring-guide.14185/
* https://www.mdsec.co.uk/2020/08/firewalker-a-new-approach-to-generically-bypass-user-space-edr-hookin
* https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa
* https://jhalon.github.io/utilizing-syscalls-in-csharp-1/
* https://jhalon.github.io/utilizing-syscalls-in-csharp-2/
* https://blog.nviso.eu/2021/10/21/kernel-karnage-part-1/
* https://jmpesp.me/malware-analysis-syscalls-example/
* https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
* https://mohamed-fakroud.gitbook.io/red-teamings-dojo/shellcoding/leveraging-from-pe-parsing-technique-to-write-x86-shellcode
* https://0xrick.github.io/win-internals/pe5/
* https://0xevilc0de.com/locating-dll-name-from-the-process-environment-block-peb/
* https://blogs.keysight.com/blogs/tech/nwvs.entry.html/2020/07/27/debugging_malwarewi-hk5u.html
* https://stackoverflow.com/questions/42789199/why-there-are-three-unexpected-worker-threads-when-a-win32-console-application-s
* https://docs.microsoft.com/
* https://kerkour.com/why-rust-for-offensive-security/
* https://zerotomastery.io/blog/why-you-should-learn-rust/
* https://github.com/skerkour/black-hat-rust
* https://github.com/trickster0/OffensiveRust
* https://github.com/Kudaes/DInvoke_rs
* https://github.com/zorftw/kdmapper-rs
* https://github.com/postrequest/link
* https://github.com/kmanc/remote_code_oxidation
* https://github.com/mdsecactivebreach/ParallelSyscalls/
* https://github.com/memN0ps/arsenal-rs/tree/main/parallel_syscalls-rs
* https://github.com/cube0x0/ParallelSyscalls/
* https://github.com/frkngksl/ParallelNimcalls
* https://github.com/Mr-Un1k0d3r/EDRs
* https://twitter.com/TheRealWover



