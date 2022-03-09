---
title: "User Mode Rootkits"
url: "/User-Mode-Rootkits"
date: 2019-05-06
---

Note: This research as been discontinued.

## Description

A user-mode rootkit is usually known as a DLL injection or code injection. A DLL injection is a technique used to inject code within the address space of a process with the use of a dynamic link library (DLL). User-mode rootkits run in ring 3, while kernel-mode rootkits run in ring 0.


## Types:

1. DLL Injection ✔
2. PE Injection
3. Process Hollowing
4. Thread Execution Hijacking
5. Hook Injection
6. Registry Modification
7. APC Injection
8. Shell Tray Injection
9. Shim Injection
10. IAT and Inline Hooking


I'll be using C++ and the Windows Application Programming Interface to demonstrate an example of a classic DLL injection.

## Classic DLL Injection via CreateRemoteThread and LoadLibrary in a Nutshell

To successfully inject a DLL inside a target process, the first thing we need to do is take a snapshot of all the processes using `CreateToolhelp32Snapshot()`.

We then iterate through the system snapshot looking for our process, including the first process we encounter, using `Process32First()` and `Process32Next()`.

Once we find the target process, we will create a handle to it with the desired access using `OpenProcess()`. 

Now that we have sufficient access and privileges to the target process, we will then allocate memory for our DLL path inside the target processes address space using `VirtualAllocEx()`. 

Once we have allocated memory, we will write the DLL path to the target process memory address, we just allocated using `WriteProcessMemory()`.

We then will create a remote thread in the target process, using `CreateRemoteThread()`, which calls `LoadLibraryA()` as our DLL path, as an argument.

`CreateRemoteThread()` uses `LoadLibrary()` which is a kernel32.dll function that loads the specified module into the address space of the calling process. 

`CreateRemoteThread()`, `NtCreateThreadEx()`, or `RtlCreateUserThread()` can be used to execute code in the target process. However, `NtCreateThreadEx()` and `RtlCreateUserThread()` are undocumented but the plan is to pass the address of `LoadLibrary()` to one these 3 functions mentioned above so that the target process can execute the DLL on our behalf.


After getting the target process to execute our code, we will wait for the execution of our loader thread to finish using `WaitForSingleObject()`.

Once finished, we can free the memory allocated for our DLL path using `VirtualFreeEx()`.


It should be noted that the `CreateRemoteThread()` techniques is not very stealthy compared to `manual mapping` and other sophisticated. However, these won't be covered in this blog.


#### The following depicts a classic DLL injection in a nutshell:

![screenshot1.gif](/User-Mode-Rootkits/screenshot1.gif)

**Figure 1: Classic DLL Injection ([EndGame](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process))** 


## Steps

[CreateToolhelp32Snapshot()](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)

Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

```cpp
HANDLE CreateToolhelp32Snapshot(
  DWORD dwFlags,
  DWORD th32ProcessID
);
```

[Process32First()](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)

Retrieves information about the first process encountered in a system snapshot.

```cpp
BOOL Process32First(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);
```

[Process32Next()](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)

Retrieves information about the next process recorded in a system snapshot.

```cpp
BOOL Process32Next(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);
```

[OpenProcess()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

Opens an existing local process object.

```cpp
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

[VirtualAllocEx()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.

```cpp
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```

[WriteProcessMemory()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.


```cpp
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

[LoadLibraryA()](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)

Loads the specified module into the address space of the calling process. The specified module may cause other modules to be loaded.

For additional load options, use the LoadLibraryEx function.

```cpp
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
);
```

[CreateRemoteThread()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

Creates a thread that runs in the virtual address space of another process.

Use the CreateRemoteThreadEx function to create a thread that runs in the virtual address space of another process and optionally specify extended attributes.


```cpp
HANDLE CreateRemoteThread(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
```

[WaitForSingleObject()](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)

Waits until the specified object is in the signaled state or the time-out interval elapses.

To enter an alertable wait state, use the WaitForSingleObjectEx function. To wait for multiple objects, use WaitForMultipleObjects.

```cpp
DWORD WaitForSingleObject(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);
```

[VirtualFreeEx()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex)

Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.

```cpp
BOOL VirtualFreeEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  dwFreeType
);
```


### Example 1: Reverse Engineering a Sample Malware Performing a Classic DLL Injection

![screenshot1.png](/User-Mode-Rootkits/screenshot1.png)

**Figure 2: Classic DLL Injection via CreateRemoteThread ([EndGame](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process))** 


### Example 2: Simple DLL

```cpp
// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		MessageBox(0, L"DLL injected sucessfully!", L"DLL Injection Demo", MB_OK);
	}
	return TRUE;
}
```
**Figure 3: dllmain.cpp**

### Example 3: Classic DLL Injector

```cpp
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

//This function can be improved, will work on it whenever I can.
bool injectDll(uintptr_t processID, const char* dllPath) {

	//This will open a handle to the target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	//if the handle is valid then execute condition
	if (hProcess) {
		// This will allocate memory for the dllpath in the target process length of the path string + null terminator
		LPVOID loadPath = VirtualAllocEx(hProcess, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

		// We write the path to the address of the memory we just allocated in the target process
		WriteProcessMemory(hProcess, loadPath, (LPVOID)dllPath, strlen(dllPath) + 1, 0);

		// This will create a Remote Thread in the target process which calls LoadLibraryA as our dllpath as an argument -> program loads our dll
		HANDLE remoteThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), loadPath, 0, 0);

		//We wait for the execution of our loader thread to finish
		WaitForSingleObject(remoteThread, INFINITE);

		// Free the memory allocated for our dll path
		VirtualFreeEx(hProcess, loadPath, strlen(dllPath) + 1, MEM_RELEASE);

		//Clean up and return true
		CloseHandle(remoteThread);
		CloseHandle(hProcess);
		return true;
	}
	//Return false if not successful
	return false;
}

uintptr_t getProcessID(const char* targetProcess, uintptr_t desiredAccess) {
	HANDLE hProcess = NULL;
	//Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes. 
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	uintptr_t processID = NULL;
	//Check if snapshot created is valid
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to take a snapshot" << std::endl;
		return false;
	}


	PROCESSENTRY32 pEntry;
	//The size of the structure, in bytes. Before calling the Process32First function, set this
	//member to sizeof(PROCESSENTRY32). If you do not initialize dwSize, Process32First fails.
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	//Loop through the processes
	do {
		//Compare the targetProcess with the process in pEntry.szExeFile (current process)
		//if the name of the process we are at right now matches the target process then we found it
		if (!strcmp(pEntry.szExeFile, targetProcess)) {
			//Process Found
			std::cout << "Found Process " << pEntry.szExeFile << " with process ID " << pEntry.th32ProcessID << std::endl;

			//Open the process with desired access and the process ID of the target process
			hProcess = OpenProcess(desiredAccess, FALSE, pEntry.th32ProcessID);
			processID = pEntry.th32ProcessID;
			CloseHandle(hSnapShot);

			//Check if handle value valid
			if (hProcess == INVALID_HANDLE_VALUE) {
				std::cout << "Failed getting a handle to the process!" << std::endl;
				return false;
			}
		}

		//Retrieves information about the first process encountered in a system snapshot.
		//Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise.
	} while (Process32Next(hSnapShot, &pEntry));

	return processID;
}

int main() {

	injectDll(getProcessID("notepad++.exe", PROCESS_ALL_ACCESS), "C:\\Users\\memN0ps\\source\\repos\\dllmain\\Debug\\dllmain.dll");
	return 0;
}
```
**Figure 4: Injector.cpp**


The source code for my classic DLL injector can be found here:

* https://github.com/memN0ps/DLL_Injector

This is separate to the `Figure 2: Classic DLL Injection via CreateRemoteThread`


## Manual Mapping
Manual Mapping is a stealthy DLL injection technique used to evade detection which emulates the LoadLibrary()  function. It works by copying the DLL image into the address space of the target process.

Since the DLL image is directly copied into the address space of the target process, the DLL will be hidden from the ToolHelp32SnapShot() function and the module list of PEB thus making detection more difficult.

More coming soon....

## References

* https://docs.microsoft.com/
* https://www.malwaretech.com/
* https://0x00sec.org/t/userland-api-monitoring-and-code-injection-detection/5565
* https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
* https://www.aldeid.com/wiki/Category:Digital-Forensics/Rootkits/User-mode-Rootkits
* http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
* https://www.youtube.com/channel/UCDk155eaoariJF2Dn2j5WKA
* https://github.com/Zer0Mem0ry
* https://guidedhacking.com/
* https://github.com/memN0ps/DLL_Injector
* https://github.com/memN0ps/Memory



