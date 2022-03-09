---
title: "Kernel Mode Rootkits"
url: "/Kernel-Mode-Rootkits"
date: 2019-05-10
---

Note: This research as been discontinued.

### Description

A kernel mode rootkit is a stealthy malicious program that allows an attacker to maintain root/SYSTEM access on a victims computer. Kernel mode rootkits run in ring 0 whilst user mode rootkits run in ring 3.

![screenshot1](/Kernel-Mode-Rootkits/screenshot1.png)

**Figure 1: Rings ([0x0sec](https://0x00sec.org/t/user-mode-rootkits-iat-and-inline-hooking/1108))**

### Building the Windows Device Driver

This is a first “hello world” example

```
#include "ntddk.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
    DbgPrint("Hello World!");
    return STATUS_SUCCESS;
}
```


### The Unload Routine
theDriverObject is an argument passed into the driver’s main function which points to a data structure that contains function pointers. One of these pointers is called the “unload routine”.

To unload the driver from memory we need to set the unload routine. Not setting this pointer will ensure that the driver remains loaded unless we reboot.

During the development phase the driver will need to be unloaded many times. We should set the unload routine so that we don’t need to reboot every time we want to test a new version of the driver.


```
// BASIC DEVICE DRIVER

#include "ntddk.h"

// This is our unload function
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
    DbgPrint("OnUnload called\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
    DbgPrint("I loaded!\n");
    
    //Initialize the pointer to the unload function
    //in the driver object
    
    theDriverObject->DriverUnload = OnUnload;
    
    return STATUS_SUCCESS;
}
```

Now we can safely load and unload the driver without rebooting.



### Fusion Rootkits: Bridging User and Kernel Modes

A fusion rootkit is a rootkit which contains bother user-mode and kernel-mode components. The user-mode part deals with most of the features, such as networking and remote control. The kernel-mode part deals with stealth and hardware access.


![screenshot2](/Kernel-Mode-Rootkits/screenshot2.png)

**Figure 2: A fusion rootkit using both user and kernel components ([Subverting the Windows Kernel](https://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319))**


User-mode programs can communicate with kernel-mode programs through many ways, one of the most common way is I/O Control (IOCTL) commands. IOCTL commands are command messages that can be defined by the driver developer.


### I/O Request Packets

A good device driver concept to understand is I/O Request Packets (IRPs). A Windows device driver needs to handle IRP to communicate with a user-mode program which are just data structures that contain buffers of data.

In the kernel an IRP is represented as a user-mode program that can open a file handle and write to it.

When a user-mode program writes the string “Hello World!” to a file handle, the kernel creates an IRP that contains the buffer and string “Hello World!” Communication between the user-mode and kernel-mode occurs via these IRPs.

To process the IRPs, the kernel driver must include functions to handle the IRP like we did in installing the unload routine. We set the appropriate function pointers in the driver object:

```
#include "ntddk.h"

NTSTATUS OnStubDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
    DbgPrint("OnUnload called\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
    int i;
    theDriverObject->DriverUnload = OnUnload;

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        theDriverObject->MajorFunction[i] = OnStubDispatch;
    }
    
    return STATUS_SUCCESS;
}
```

![screenshot3](/Kernel-Mode-Rootkits/screenshot3.png)

**Figure 3: Routing of I/O calls through “major-function” pointers. ([Subverting the Windows Kernel](https://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319))**


The Major Functions are stored in an array and the locations are marked with the defined values IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_DEVICE_CONTROL as shown in the sample code and Figure 3.

The OnStubDispatch function is a stub routine that does nothing and all of the IRP defined values are set to point to it.

For each major function we would most likely create a seperate function in a real driver. For example, assuming we will be handling the READ and WRITE events, each of these events is triggered when a user-mode program calls ReadFile or WriteFile with a handle to the driver.

A more complete driver might handle additional functions, such as those for closing a file or sending an IOCTL command. An example set of major function pointer follows:

```
DriverObject->MajorFunction[IRP_MJ_CREATE] = MyOpen;
DriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;
DriverObject->MajorFunction[IRP_MJ_READ] = MyRead;
DriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyIoControl;
```

The driver needs to specify a function that will be called for each major function. For example, the driver might contain these functions:


```
NTSTATUS MyOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // do something
    ...
    return STATUS_SUCCESS;
}

NTSTATUS MyClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // do something
    ...
    return STATUS_SUCCESS;
}

NTSTATUS MyRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // do something
    ...
    return STATUS_SUCCESS;
}

NTSTATUS MyWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // do something
    ...
    return STATUS_SUCCESS;
}

NTSTATUS MyIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    ULONG FunctionCode;
    
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    FunctionCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    
    switch (FunctionCode)
    {
        // do something
        ...
    }
    return STATUS_SUCCESS;
}
```



![screenshot4](/Kernel-Mode-Rootkits/screenshot4.png)

**Figure 4: The kernel driver can define specific callback functions for each type of “major function”. ([Subverting the Windows Kernel](https://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319))**


Figure 4 shows how user-mode program calls are routed through the Major Function array and eventually to the driver defined functions MyRead, MyWrite and MyIOCTL.

We now know how function calls in user-mode translate to function calls in kernel mode. We can now cover how you can expose your driver to user-mode using file objects.

### Creating a File Handle

File handles is an important concept to understand because, in order to use a kernel driver from a user-mode program, the user-mode program must open a file handle to the driver. For this to happen, the driver must first register a named device first, then the user-mode program will open the named device as though it were a file which is very similar to UNIX systems, everything is treated like a file.

For example, the kernel driver registers a device using the following:

```
const WCHAR deviceNameBuffer[] = L"\\Device\\MyDevice";
PDEVICE_OBJECT g_RootkitDevice; // Global pointer to our device object
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS ntStatus;
    UNICODE_STRING deviceNameUnicodeString;

    // Set up our name and symbolic link.
    RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);

    // Set up the device.                       // For driver extension
    ntStatus = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString, 0x00001234, 0, TRUE, &g_RootkitDevice);
...
```

In the following code snippet, the DriverEntry routine promptly creates a device named MyDevice. Note the fully qualified path that is used in this call:

`const WCHAR deviceNameBuffer[] = L"\\Device\\MyDevice";`

In the following code snippet, the “L” prefix causes the string to be defined in UNICODE, which is required for the API call. A user-mode program can open the device as though it were a file, once the device is created:

```
hDevice = CreateFile("\\\\Device\\MyDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

if (hDevice == ((HANDLE)-1))
    return FALSE;
```

The file handle can be used as a parameter in user-mode functions such as ReadFile and WriteFile once it is opened, it can also be used to make IOCTL calls. IRP’s are generated with these operations which can then be handled in the driver program.

File handles are easy to open and use from user-mode. We will now explore symbolic links which makes file handles easier to use.

### Adding a Symbolic Link

Another important concept to understand is symbolic links. To make file handles easier for user-mode programs, some drivers will use symbolic links, which is not mandatory but it’s nice to have since it’s easier to remember.

Some rootkits will use symbolic links while others will skip this technique. A rootkit which uses this technique would create a device and then make a call to IoCreateSymbolicLink to create the symbolic link.

```
const WCHAR deviceLinkBuffer[] = L"\\DosDevices\\vicesys2";
const WCHAR deviceNameBuffer[] = L"\\Device\\vicesys2";

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
    NTSTATUS ntStatus;
    
    UNICODE_STRING deviceNameUnicodeString;
    UNICODE_STRING deviceLinkUnicodeString;
    
    // Set up our name and symbolic link.
    
    RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
    
    RtlInitUnicodeString(&deviceLinkUnicodeString, deviceLinkBuffer);
    
    // Set up the device
    //
                                                // For driver extension
    ntStatus = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString FILE_DEVICE_ROOTKIT, 0, TRUE, &g_RootkitDevice);
    
    if (NT_SUCCESS(ntStatus))
        ntStatus = IoCreateSymbolicLink(&deviceLinkUnicodeString, &deviceNameUnicodeString);
```

A user-mode program can open a handle to the device using the string \\.\MyDevice , after a symbolic link has been created. It is not require to create a symbolic link but it makes it easier for the user-mode code to find the driver.

```
hDevice = CreateFile("\\\\.\\MyDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

if (hDevice == ((HANDLE)-1))
    return FALSE;
```

We have discussed how to communicate between user mode and kernel mode using a file handle. The next step is to discuss how you load a device driver.


### Loading the Rootkit

### The Quick-and-Dirty Way to Load a Driver

### The Right way to Load a Driver

Coming soon…


### References
* https://0x00sec.org/t/user-mode-rootkits-iat-and-inline-hooking/1108
* https://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319

### Credits
All credits go to “Subverting the Windows Kernel”, an awesome book by Greg Hoglund
