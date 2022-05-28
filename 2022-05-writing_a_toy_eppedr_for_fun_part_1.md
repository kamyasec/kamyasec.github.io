# Writing a toy EPP/EDR for fun: Part 1

## Motivation

I just want to learn a bit about Kernel driver developement, Windows internals and endpoint security from the perspective of a defender. Writing a toy AV/EDR/EPP/XDR/whatever the fuck seems like a fun way to accomplish this.

### Threat model

I guess I should say something about how I perceive the threat that I want my toy EPP to protect against.

* Attacker has full control over user-land, including administrator access
* Attacker is unable to escalate to kernel-space (for some reason)

I should also say that I will be focusing on behavioural detection/prevention, foregoing signatures entirely. Proper EDR/EPPs will probably use signatures in conjunction with other techniques.

## Setting up a dev environment

See [voidsec's blog post](https://voidsec.com/windows-drivers-reverse-engineering-methodology/).

You also need Visual Studio, the Windows SDK and the Windows Driver Kit on your dev machine. See [Microsoft's website](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) for more on that. It could be useful to have WinDbg on your test machine as well.


## Getting to work

Beware: Code is shoddy, sort of low-effort (well, really it's created by someone who does not know what they are doing, but it is functionally equivalent to low-effort stuff), and may crash on you. We don't do error handling around here.

Most modern EDR/EPPs seem to like living in userland with user-land hooks and user-land processes. According the threat model outlined above, I don't think this is the right call. As a consequence, my EDR/EPP will live in the kernel as a kernel-mode driver. I'll say I have no clue why most EDRs do what they do, but I'm sure they have their reasons.

After the implementation of PatchGuard in the kernel, just patching shit (LOL) will have you bluescreening. That means SSDT-hooking is no longer possible. I believe some EDR/EPPs rely on Event Tracing for Windows (ETW), but the source of information for this is also from user-land (I think?), thus untrustworthy. So our approach to accomplish all of this, is via kernel callbacks. Once upon a time, I thought we could use the Kernel Shim Engine for this, but alas.

There is nothing new in this post, I am just doodling. Pavel Yosifovich (@zodiacon) demonstrates a bunch of stuff in his "Windows Kernel Programming" book (which is a must-read). See the [Github page](https://github.com/zodiacon/windowskernelprogrammingbook), and the [book sales page](https://leanpub.com/windowskernelprogramming).


### Registering ALL THE THINGS

First, we need to define some global variables for our EDR. I have cheated, so I am writing this after having done everything else. Therefore I know we need:

```C
typedef struct _CUSTOM_PROCESS_INFO_ENTRY {
    HANDLE PID;
    HANDLE PPID;
    BOOLEAN is_whitelisted;
    LIST_ENTRY list_entry;
} CUSTOM_PROCESS_INFO_ENTRY, * PCUSTOM_PROCESS_INFO_ENTRY;


typedef struct _Globals {
    PVOID process_open_handle;
    int current_ptr;
    LIST_ENTRY process_list;
    KSPIN_LOCK spinlock;
} Globals, * PGlobals;
```

which makes our code somewhat easy to expand on in the future. We also make some helper functions to use our process linked list, but they aren't really that interesting. Just remember to free shit.

Now, lets actually register ALL the things. First, we register a process callback! I am told real EDRs use both ```PsSetCreateProcessNotifyRoutineEx``` and ```PsSetCreateProcessNotifyRoutine```, but I'll go with just the former.

```C
...

VOID process_creation_callback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {

    if (!CreateInfo) { // If CreateInfo is NULL, the process is exiting!

        PCUSTOM_PROCESS_INFO_ENTRY procinfo = get_entry_from_procid(ProcessId);

        if (procinfo) {
            DBG_LOG("[!] Process with PID %i exited. Freeing memory.", ProcessId);
            remove_entry_from_proclist(procinfo);
        }

        return;
    }

    /*PACCESS_TOKEN access_token = PsReferencePrimaryToken(Process);

    if (access_token) {
        
        PTOKEN_OWNER token_owner = NULL;
        if (SeQueryInformationToken(access_token, TokenOwner, &token_owner) == STATUS_SUCCESS) {
            UNICODE_STRING user = { 0, 0, NULL };
            if (RtlConvertSidToUnicodeString(&user, token_owner->Owner, TRUE) == STATUS_SUCCESS) {
                //DBG_LOG("\\\\-- Process owner SID: %wZ.", user);
                ExFreePool(user.Buffer);
            }
            ExFreePool(token_owner);
        }
    }*/

    PCUSTOM_PROCESS_INFO_ENTRY procentry = (PCUSTOM_PROCESS_INFO_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(CUSTOM_PROCESS_INFO_ENTRY), DRIVER_TAG);
    procentry->PID = ProcessId;
    procentry->PPID = CreateInfo->ParentProcessId;

    if (running_from_secure_path(Process)) {
        procentry->is_whitelisted = TRUE;
    }
    else {
        procentry->is_whitelisted = FALSE;
    }
    insert_into_proclist(procentry);
}

...

...
NTSTATUS status = 0;
	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)process_creation_callback, FALSE);
...
```

Simple right? I also included some testing and debug prints which you can experiment with on your own. Just beware, too much debugprinting will really slow down your system (at least it did to mine).

```running_from_secure_path``` seems interesting right? Well...

### Establishing a baseline

Lets imagine that when we start our computer, there is no evil actor on it at that moment. The attacker gains attack at some point in time after booting. Consequentially we may assume that certain processes running are legitimate. Ideally we'd check that they are signed by Microsoft, but I am lazy, so I'll just whitelist ```C:\windows\system32``` for now. This is what ```running_from_secure_path``` does. I mean, I think if we are creative, there is a way this could work in the general case maybe. More on that in a later post. Keep in mind that this is just messing around, not actually making a real EPP/EDR. If you want to actually do this for real you could use signatures, like in this [Cyberreason blog post](https://www.cybereason.com/blog/code-integrity-in-the-kernel-a-look-into-cidll).

Code:

```C
BOOLEAN running_from_secure_path(PEPROCESS process) {
    BOOLEAN return_value = FALSE;
    PUNICODE_STRING full_path = NULL;

    SeLocateProcessImageName(process, &full_path);

    UNICODE_STRING sys32_path = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\System32\\");
    
    UNICODE_STRING sys32_candidate_path = { sys32_path.Length, full_path->MaximumLength, full_path->Buffer};
    if (RtlCompareUnicodeString(&sys32_path, &sys32_candidate_path, TRUE) == 0) {
        //DBG_LOG("[+] Executable (%wZ) is running from system32-folder.", full_path);
        return_value = TRUE;
    }

sec_path_free:
    ExFreePool(full_path);
  
    return return_value;
}
```

We can use basically the same code for other heuristics as well, like preventing stuff from executing from ```C:\Windows\Temp``` or ```C:\User\username\Downloads```. If we find that a process creation seems suspicious we can deny its creation by adding the following snippet to our ```process_creation_callback```-function.

```C
if(heuristics_process_is_suspicious(Process)) {
    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    return;
}
```

Okay, so this will probably not stop any attackers. However, it will constrain the places in which they may operate which is still a win in my opinion. And it is actually kinda cool. Lets look at another way to constrain an attacker.

### Stopping LSASS memory dumping

Lets try to prevent the dumping of LSASS memory. Protecting LSASS from being dumped could make an attackers task much more difficult. Using PPL or any E5 license shit is cheating.


Register our function-callback for when any process tries to open or duplicate a handle to a process. This could be the kernel, or it could be a user-land process. Meaning our function is called every time a handle is opened or duplicated - prior to it completing.

```C
NTSTATUS process_callback_handler_open_registration() {
    OB_OPERATION_REGISTRATION opreg[] = { { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, process_callback_handler_open, NULL } };
    OB_CALLBACK_REGISTRATION cbreg = { OB_FLT_REGISTRATION_VERSION, 1, RTL_CONSTANT_STRING(L"1"), NULL, opreg };
    NTSTATUS status = ObRegisterCallbacks(&cbreg, &GLOBS.process_open_handle);

    return status;
}
```


This will run a bazillion times, because handles are opened all the time. This means we need to be somewhat efficient, and return early if it seems legitimate. I think no process normally opens a handle with PROCESS_VM_READ to lsass, meaning if the process being opened a handle to is lsass, AND the desired access mask contains PROCESS_VM_READ, it is probably bad. Maybe. I don't know, but I think so.


So our callback will look something like this:
```C
OB_PREOP_CALLBACK_STATUS process_callback_handler_open(PVOID registration_context, POB_PRE_OPERATION_INFORMATION operation_context) {
...
...
...

     UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe"); // Don't hard code it like this, thats lazy.

    if (RtlCompareUnicodeString(target_name, &lsass, TRUE) == 0) {
            
        if ((operation_context->Parameters->CreateHandleInformation.DesiredAccess & (ACCESS_MASK)(ULONG)0x10) == (ACCESS_MASK)(ULONG)0x10) {

            if (operation_context->Operation == OB_OPERATION_HANDLE_CREATE) {
                DBG_LOG("[+] Target PID: %i (%wZ) | Caller PID: %i (%wZ)", target_pid, target_name, source_pid, source_name);
                DBG_LOG("     \\-- ACCESS_MASK contains PROCESS_VM_READ on lsass.exe. Stripping access!");
                operation_context->Parameters->CreateHandleInformation.DesiredAccess &= ~((ACCESS_MASK)0x10);
                return OB_PREOP_SUCCESS;
            }
        }
    }
...
}
```

Running this code, and dumping with nanodump:

```
beacon> nanodump -w C:\temp\lsass.dmp
[*] Running NanoDump BOF
[+] host called home, sent: 46172 bytes
[-] Failed to read LSASS, status: STATUS_ACCESS_DENIED
```

Dumping LSASS using the ["MalSecLogon"-technique](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html) however still works. Some other duplicate handling techniques will also probably work, but I am too lazy to check.


Extending the (essentially) same code to the case where the ```operation_context->Operation``` is ```OB_OPERATION_HANDLE_DUPLICATE``` will stop MalSecLogon from dumping LSASS as well.

```C
if (operation_context->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
    DBG_LOG("[+] Target PID: %i (%wZ) | Caller PID: %i (%wZ)", target_pid, target_name, source_pid, source_name);
    DBG_LOG("     \\-- ACCESS_MASK contains PROCESS_VM_READ on lsass.exe. Stripping access!");
    operation_context->Parameters->DuplicateHandleInformation.DesiredAccess &= ~((ACCESS_MASK)0x10);
    return OB_PREOP_SUCCESS;
}
```


Now the only technique left that still works is ```load_ssp``` (at least from nanodump). ```load_ssp``` registers a new security support provider (SSP). This essentially makes LSASS load a new module, which can be used to dump its own memory (i.e. the lsass process). 

I thought we could protect against this as well by registering a ```PLOAD_IMAGE_NOTIFY_ROUTINE``` using ```PsSetLoadImageNotifyRoutine``` and block upon loading of non-Microsoft signed DLLs into the lsass-process. This would obviously break custom stuff. However it seems like the load callback is called after the DLL has been loaded, which makes it less than ideal for prevention, though we can log it.

```C
void process_callback_imageload(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {

    if (ImageInfo->SystemModeImage) { // Kernel module
        return;
    }

    if (ProcessId == NULL) { // Should not happen, but it is a somewhat trivial check.
        return;
    }

    PEPROCESS process;

    PsLookupProcessByProcessId(ProcessId, &process);

    if (!process) {
        return;
    }

    PUNICODE_STRING process_name = NULL;
    SeLocateProcessImageName(process, &process_name);


    UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe"); // You probably dont want to not hard code it like this, right?

    if (RtlCompareUnicodeString(process_name, &lsass, TRUE) == 0) {
        // According to @zodiacon FullImageName is not trustworthy, so ideally we should find it properly using the extended information.
        DBG_LOG("[+] Looks like lsass is trying to load %wZ", FullImageName); // This will log legitimate DLLs being loaded on demand, which imo is interesting if nothing else.

        if (ImageInfo->ImageSignatureType == SeImageSignatureNone || ImageInfo->ImageSignatureLevel <= SE_SIGNING_LEVEL_UNSIGNED) {
                DBG_LOG("[!] Suspicious, unsigned module loaded into LSASS.");
            }
        }
    }
}
```


Perhaps we can use minifilters instead, to block lsass from opening suspicious (DLL) files? Anyway, I think that might be another post entirely. Lets leave mitigating ```load_ssp``` on the TODO-list for now.

Obviously, just running lsass.exe as PPL would do all of this for you, but thats no fun.



### Detecting thread creation in RWX memory

When a callback function registered with ```PsSetCreateThreadNotifyRoutineEx``` is called, the created user-land thread will be in ```ntdll!RtlCreateUserThreadStart```. This function returns to ```ntdll!Kernel32ThreadInitThunkFunction``` which is a pointer to ```kernel32!BaseThreadInitThunk```. This all makes it kinda difficult to get the "main" address of the created thread. What we are after is the ```my_legit_address``` argument in a ```CreateThread(0, 0, (LPTHREAD_START_ROUTINE)my_legit_address, 0, 0, 0);``` call (or the equivalent in ```CreateRemoteThread```, ```NtCreateThreadEx``` etc).

Lucky for us, we can obtain the address using ```ZwQueryInformationThread```, right? No. Well, maybe I'm doing something wrong, but I never got ```ZwQueryInformationThread(ThreadId, ThreadQuerySetWin32StartAddress, &start_address, sizeof(PVOID), NULL);``` working. It just gave me an invalid handle error.

Okay, but the ```_ETHREAD``` structure contains a field for the start address. Microsoft however doesn't want to share their structure information with us in a header file, so we can construct our own. Breaking in the debugger and dumping the structure using the symbols provided by MS: ```dt nt!_ETHREAD``` we can just modify and use that one. Beware though, it seems like this structure changes somewhat frequently. I use the Windows SDK for 10.0.1941.685 for this specific machine. As we are only interested in the ```Win32StartAddress``` parameter (for now), we can use the following:

```C
typedef struct _my_ETHREAD {
    char pad_0x00[0x690];
    PVOID startaddress;
    char pad_0x698[0x178];
} my_ETHREAD, * Pmy_ETHREAD;
```

In the thread creation callback function, we obtain the starting address like so:

```C
PETHREAD thread = NULL;
PsLookupThreadByThreadId(ThreadId, &thread);

Pmy_ETHREAD m = (Pmy_ETHREAD)thread;
DBG_LOG("Thread: %p. Start address: %p", thread, m->startaddress);
```

Next, we obtain a reference to the EPROCESS-structure representing the process in the executive, use this to get a traditional "handle", which we use with ```ZwQueryVirtualMemory``` to obtain the ```MEMORY_BASIC_INFORMATION``` of the memory the thread is starting from. Code:

```C
PEPROCESS process = PsGetThreadProcess(thread);

HANDLE hProc = NULL;

status = ObOpenObjectByPointer(process, 0, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc);

MEMORY_BASIC_INFORMATION mbi = { 0 };
status = ZwQueryVirtualMemory(hProc, start_address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);

if (status != STATUS_SUCCESS) {
    DBG_LOG("[-] ZwQueryVirtualMemory failed with status %x", status);
    break;
}
```

Now we can easily determine whether the memory allocated for the intercepted thread is RWX like so:
```C
if (mbi.AllocationProtect == 0x40) {
    DBG_LOG("[!] Thread executing from RWX memory.");
}
```

What happens next is really up to the implementer. For PoCing I'll settle for just killing the process. Some implementations may kill the entire process chain - down all the way, and up until a legitimate process is found, for a definition of legitimate.

```C
ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
```

It is surprisingly satisfying when my calc-payload using RWX memory doesn't open calc.exe. Almost as satisfying as popping shells.


## Lessons learned

Kernel programming is fucking difficult. Callbacks also feels weird, because the information you see is not 1-1 with what is happening in user-land. It makes the whole process of identifying suspicious things way more difficult than I think it should be. I guess I understand why there are so many AV/EPP/EDR vendors using user-land hooks. You just feel more free there. Could be my inexperience with Kernel drivers though. I wish Microsoft made it possible to hook Zw-functions in the kernel, perhaps using something with as simple a interface as the Kernel Shim Engine. There are probably good reasons to not allow that though.

## Further reading

* https://leanpub.com/windowskernelprogramming
* https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals
* https://www.unknowncheats.me/ (seriously)
    * E.g. https://github.com/TheCruZ/Apex_Legends_Driver_Cheat/tree/699250f6a9c0bc9c11d5e410742f253aeb884ca2/StrunderSv/StrunderSv
* https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/
* MSDN
* https://doxygen.reactos.org/


## Appendix

Full code:

```C
#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

#define DRIVER_TAG 'abcd'

typedef struct _my_ETHREAD {
    char pad_0x00[0x690];
    PVOID startaddress;
    char pad_0x618[0x178];
} my_ETHREAD, * Pmy_ETHREAD;


typedef struct _CUSTOM_PROCESS_INFO_ENTRY {
    HANDLE PID;
    HANDLE PPID;
    BOOLEAN is_whitelisted;
    LIST_ENTRY list_entry;
} CUSTOM_PROCESS_INFO_ENTRY, * PCUSTOM_PROCESS_INFO_ENTRY;


typedef struct _Globals {
    PVOID ntoskrnladdr;
    ULONG ntoskrnlsize;
    PVOID process_open_handle;
    int current_ptr;
    LIST_ENTRY process_list;
    KSPIN_LOCK spinlock;
} Globals, * PGlobals;

#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[my_first_edr] [" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__)

Globals GLOBS;
DRIVER_INITIALIZE DriverEntry;


NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject);


VOID insert_into_proclist(PCUSTOM_PROCESS_INFO_ENTRY entry) {

    if (entry == NULL) {
        return;
    }

    KIRQL oldirql = { 0 };
    KeAcquireSpinLock(&GLOBS.spinlock, &oldirql);
    InsertTailList(&GLOBS.process_list, &entry->list_entry);
    KeReleaseSpinLock(&GLOBS.spinlock, oldirql);
}

VOID remove_entry_from_proclist(PCUSTOM_PROCESS_INFO_ENTRY entry) {

    if (entry == NULL) {
        return;
    }

    KIRQL oldirql = { 0 };
    KeAcquireSpinLock(&GLOBS.spinlock, &oldirql);

    RemoveEntryList(&entry->list_entry);
    ExFreePool(entry);

    KeReleaseSpinLock(&GLOBS.spinlock, oldirql);
}

PCUSTOM_PROCESS_INFO_ENTRY get_entry_from_procid(HANDLE ProcessId) {
    KIRQL oldirql = { 0 };
    KeAcquireSpinLock(&GLOBS.spinlock, &oldirql);
    LIST_ENTRY* list_head = &GLOBS.process_list;
    LIST_ENTRY* entry = list_head->Flink;
    while (entry != list_head && entry != NULL) {

        PCUSTOM_PROCESS_INFO_ENTRY procinfo = CONTAINING_RECORD(entry, CUSTOM_PROCESS_INFO_ENTRY, list_entry);

        if (!procinfo) {
            break;
        }

        if (procinfo->PID == ProcessId) {
            KeReleaseSpinLock(&GLOBS.spinlock, oldirql);
            return procinfo;
        }

        entry = entry->Flink;
    }

    KeReleaseSpinLock(&GLOBS.spinlock, oldirql);
    return NULL;
}


BOOLEAN running_from_secure_path(PEPROCESS process) {
    // Check if ran from C:\Windows\System32. Don't do this in the real world.
    BOOLEAN return_value = FALSE;
    PUNICODE_STRING full_path = NULL;

    SeLocateProcessImageName(process, &full_path);

    UNICODE_STRING sys32_path = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\System32\\");
    
    UNICODE_STRING sys32_candidate_path = { sys32_path.Length, full_path->MaximumLength, full_path->Buffer};
    if (RtlCompareUnicodeString(&sys32_path, &sys32_candidate_path, TRUE) == 0) {
        //DBG_LOG("[+] Executable (%wZ) is running from system32-folder.", full_path);
        return_value = TRUE;
    }

    ExFreePool(full_path);
    return return_value;
}

BOOLEAN running_from_sus_path(PEPROCESS process) {
    BOOLEAN return_value = FALSE;
    PUNICODE_STRING full_path = NULL;

    SeLocateProcessImageName(process, &full_path);

    UNICODE_STRING sus1 = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\Temp\\");
    UNICODE_STRING sus1_candidate_path = { sus1.Length, full_path->MaximumLength, full_path->Buffer };
    if (RtlCompareUnicodeString(&sus1, &sus1_candidate_path, TRUE) == 0) {
        return_value = TRUE;
        goto free;
    }

    UNICODE_STRING sus2 = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\Tasks\\");
    UNICODE_STRING sus2_candidate_path = { sus2.Length, full_path->MaximumLength, full_path->Buffer };
    if (RtlCompareUnicodeString(&sus2, &sus2_candidate_path, TRUE) == 0) {
        return_value = TRUE;
        goto free;
    }

free:
    ExFreePool(full_path);

    return return_value;
}

#pragma warning(disable : 4100)
VOID process_creation_callback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {

    if (!CreateInfo) { // If CreateInfo is NULL, the process is exiting!

        PCUSTOM_PROCESS_INFO_ENTRY procinfo = get_entry_from_procid(ProcessId);

        if (procinfo) {
            //DBG_LOG("[+] Process with PID %i exited. Freeing memory.", ProcessId);
            remove_entry_from_proclist(procinfo);
        }

        return;
    }

    PEPROCESS parent_process = NULL;
    if (PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parent_process) == STATUS_SUCCESS) {
        if (running_from_sus_path(Process) || running_from_sus_path(parent_process)) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }
    }

    PCUSTOM_PROCESS_INFO_ENTRY procentry = (PCUSTOM_PROCESS_INFO_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(CUSTOM_PROCESS_INFO_ENTRY), DRIVER_TAG);
    procentry->PID = ProcessId;
    procentry->PPID = CreateInfo->ParentProcessId;

    if (running_from_secure_path(Process)) {
        procentry->is_whitelisted = TRUE;
    }
    else {
        procentry->is_whitelisted = FALSE;
    }
    insert_into_proclist(procentry);

    //DBG_LOG("[+] Process created. ImageFileName: %wZ. | Commandline: %wZ | PID: %i | PPID: %i", CreateInfo->ImageFileName, CreateInfo->CommandLine, ProcessId, CreateInfo->ParentProcessId);

}

BOOLEAN is_child_process(HANDLE a, HANDLE b) {

    PCUSTOM_PROCESS_INFO_ENTRY a_entry = get_entry_from_procid(a);
    PCUSTOM_PROCESS_INFO_ENTRY b_entry = get_entry_from_procid(b);

    if (a_entry && b_entry) {

        if (a_entry->PPID == b_entry->PID) {
            return TRUE;
        }
    }

    return FALSE;
}


BOOLEAN heuristics_allow_handle_creation(PEPROCESS source, PUNICODE_STRING source_name, PEPROCESS target, PUNICODE_STRING target_name, POB_PRE_OPERATION_INFORMATION operation_context) {

    HANDLE source_pid = PsGetProcessId(source);
    PCUSTOM_PROCESS_INFO_ENTRY procinfo = get_entry_from_procid(source_pid);
    if (procinfo && procinfo->is_whitelisted) {
        return TRUE;
    }

    if (procinfo == NULL) {
        PCUSTOM_PROCESS_INFO_ENTRY procentry = (PCUSTOM_PROCESS_INFO_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(CUSTOM_PROCESS_INFO_ENTRY), DRIVER_TAG);
        procentry->PID = source_pid;
        procentry->PPID = 0;
        procentry->is_whitelisted = FALSE;
        insert_into_proclist(procentry);
        procinfo = procentry;
    }

    if (running_from_secure_path(source)) {
        return TRUE;
    }

    if (running_from_sus_path(source)) {
        return FALSE;
    }


    if (is_child_process(PsGetProcessId(target), PsGetProcessId(source))) { 
        return TRUE;
    }

    return FALSE;
}

#pragma warning(disable : 4189)
OB_PREOP_CALLBACK_STATUS process_callback_handler_open(PVOID registration_context, POB_PRE_OPERATION_INFORMATION operation_context) {

    if (operation_context->KernelHandle) {
        //DBG_LOG("[+] Returning early from process_callback_handler_open (kernel handle).");
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS target_process = (PEPROCESS)operation_context->Object;
    PEPROCESS source_process = PsGetCurrentProcess();
    HANDLE target_pid = PsGetProcessId(target_process);
    HANDLE source_pid = PsGetProcessId(source_process);

    PUNICODE_STRING target_name = NULL;
    PUNICODE_STRING source_name = NULL;

    SeLocateProcessImageName(target_process, &target_name);
    SeLocateProcessImageName(source_process, &source_name);

    //DBG_LOG("[+] Target PID: %i (%wZ) | Caller PID: %i (%wZ)", target_pid, target_name, source_pid, source_name);

    UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe"); // You probably dont want to not hard code this...

    if (RtlCompareUnicodeString(target_name, &lsass, TRUE) == 0) {
            
        if ((operation_context->Parameters->CreateHandleInformation.DesiredAccess & (ACCESS_MASK)(ULONG)0x10) == (ACCESS_MASK)(ULONG)0x10) {

            if (operation_context->Operation == OB_OPERATION_HANDLE_CREATE) {
                DBG_LOG("[+] Target PID: %i (%wZ) | Caller PID: %i (%wZ)", target_pid, target_name, source_pid, source_name);
                DBG_LOG("     \\-- ACCESS_MASK contains PROCESS_VM_READ on lsass.exe. Stripping access!");
                operation_context->Parameters->CreateHandleInformation.DesiredAccess &= ~((ACCESS_MASK)0x10);
                goto free_shit;
            }

            if (operation_context->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                DBG_LOG("[+] Target PID: %i (%wZ) | Caller PID: %i (%wZ)", target_pid, target_name, source_pid, source_name);
                DBG_LOG("     \\-- ACCESS_MASK contains PROCESS_VM_READ on lsass.exe. Stripping access!");
                operation_context->Parameters->DuplicateHandleInformation.DesiredAccess &= ~((ACCESS_MASK)0x10);
                goto free_shit;
            }
        }
    }

    if (operation_context->Operation == OB_OPERATION_HANDLE_CREATE) {

        if ((operation_context->Parameters->CreateHandleInformation.DesiredAccess & (ACCESS_MASK)(ULONG)0x8) == (ACCESS_MASK)(ULONG)0x8) {

            if (heuristics_allow_handle_creation(source_process, source_name, target_process, target_name, operation_context)) {
                goto free_shit;
            }
            else {
                // Strip access because the heuristics told us to
                //DBG_LOG("[!] Suspicious handle creation detected. Stripping access.");
                operation_context->Parameters->CreateHandleInformation.DesiredAccess &= ~((ACCESS_MASK)0x18);
                goto free_shit;
            }
        }
    }

    if (operation_context->Operation == OB_OPERATION_HANDLE_DUPLICATE) {

        if ((operation_context->Parameters->DuplicateHandleInformation.DesiredAccess & (ACCESS_MASK)(ULONG)0x8) == (ACCESS_MASK)(ULONG)0x8) {

            if (heuristics_allow_handle_creation(source_process, source_name, target_process, target_name, operation_context)) {
                goto free_shit;
            }
            else {
                // Strip access because the heuristics told us to
                //DBG_LOG("[!] Suspicious handle creation detected. Stripping access.");
                operation_context->Parameters->DuplicateHandleInformation.DesiredAccess &= ~((ACCESS_MASK)0x18);
                goto free_shit;
            }
        }
    }
    
free_shit:
    if (target_name) {
        ExFreePool(target_name);
    }
    if (source_name) {
        ExFreePool(source_name);
    }
ret:
    return OB_PREOP_SUCCESS;
}

void process_callback_imageload(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {

    if (ImageInfo->SystemModeImage) {
        return;
    }

    if (ProcessId == NULL) {
        return;
    }

    PEPROCESS process;

    PsLookupProcessByProcessId(ProcessId, &process);

    if (!process) {
        return;
    }

    PUNICODE_STRING process_name = NULL;
    SeLocateProcessImageName(process, &process_name);


    UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe"); // You probably dont want to not hard code this to that device?

    if (RtlCompareUnicodeString(process_name, &lsass, TRUE) == 0) {
        DBG_LOG("[+] Looks like lsass is trying to load %wZ", FullImageName);

        if (ImageInfo->ImageSignatureType == SeImageSignatureNone || ImageInfo->ImageSignatureLevel <= SE_SIGNING_LEVEL_UNSIGNED) {
            // According to @zodiacon FullImageName is not trustworthy, so ideally we should find it properly using the extended information.
            DBG_LOG("[+] Looks like lsass is trying to load %wZ", FullImageName); // This will log legitimate DLLs being loaded on demand, which imo is interesting if nothing else.

            
        }
    }
}

NTSTATUS process_callback_handler_open_registration() {
    OB_OPERATION_REGISTRATION opreg[] = { { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, process_callback_handler_open, NULL } };
    OB_CALLBACK_REGISTRATION cbreg = { OB_FLT_REGISTRATION_VERSION, 1, RTL_CONSTANT_STRING(L"6969.420"), NULL, opreg };
    NTSTATUS status = ObRegisterCallbacks(&cbreg, &GLOBS.process_open_handle);

    return status;
}

VOID process_callback_handler_open_remove() {
    if (GLOBS.process_open_handle != NULL) {
        ObUnRegisterCallbacks(GLOBS.process_open_handle);
    }
}

NTSTATUS process_callback_imageload_registration() {
    return PsSetLoadImageNotifyRoutine(process_callback_imageload);
}

VOID process_callback_imageload_remove() {
    PsRemoveLoadImageNotifyRoutine(process_callback_imageload);
}

VOID print_mbi(PMEMORY_BASIC_INFORMATION mbi) {
    DBG_LOG("AllocBase: %p | AllocProtect: %x | BaseAddress: %p | Protect: %x | State: %x | Type: %x | RegionSize: %x", 
        mbi->AllocationBase, mbi->AllocationProtect, mbi->BaseAddress, mbi->Protect, mbi->State, mbi->Type, mbi->RegionSize);
}


VOID thread_creation_callback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {

    if (!Create) { // Thread exit?
        return;
    }
    NTSTATUS status = 0;
    PETHREAD thread = NULL;
    PsLookupThreadByThreadId(ThreadId, &thread);
    
    PEPROCESS process = PsGetThreadProcess(thread);
    PUNICODE_STRING process_name = NULL;
    SeLocateProcessImageName(process, &process_name);
    //DBG_LOG("[+] Process name: %wZ", process_name);
      
    Pmy_ETHREAD m = (Pmy_ETHREAD)thread;
    //DBG_LOG("\\\\-- Thread: %p. Start address: %p", thread, m->startaddress);
    PVOID start_address = m->startaddress;

    HANDLE hProc = NULL;
    status = ObOpenObjectByPointer(process, 0, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc);

    do {
        if (status == STATUS_SUCCESS) {

            MEMORY_BASIC_INFORMATION mbi = { 0 };
            status = ZwQueryVirtualMemory(hProc, start_address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);

            if (status != STATUS_SUCCESS) {
                DBG_LOG("[-] ZwQueryVirtualMemory failed with status %x", status);
                break;
            }

            //DBG_LOG("\\\\-- ZwQueryVirtualMemory gave status code %x (queries memory at %p)", status, start_address);
            //print_mbi(&mbi);
            if (mbi.AllocationProtect == 0x40 || mbi.Protect == 0x40) {
                DBG_LOG("[!] Thread executing from RWX memory. Terminating process with PID %i", ProcessId);
                print_mbi(&mbi);
                ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
            }
        }
        else {
            DBG_LOG("[-] Could not open handle.");
        }
    } while (FALSE);

    ExFreePool(process_name);
}


NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)process_creation_callback, TRUE);
    PsRemoveCreateThreadNotifyRoutine(thread_creation_callback);
    process_callback_handler_open_remove();
    process_callback_imageload_remove();

	DBG_LOG("[+] Unloaded driver.");
	return STATUS_SUCCESS;
}


UNICODE_STRING ZwQueryInformationThread_str = RTL_CONSTANT_STRING(L"ZwQueryInformationThread");
typedef NTSTATUS(NTAPI* ZwQueryInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

ZwQueryInformationThread_t ZwQueryInformationThread = NULL;

VOID initialize_internal_functions() {

    ZwQueryInformationThread = (ZwQueryInformationThread_t)MmGetSystemRoutineAddress(&ZwQueryInformationThread_str);
    DBG_LOG("[+] ZwQueryInformationThread is at %p", ZwQueryInformationThread);                                  
}

#pragma warning(disable : 4100)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {


	DBG_LOG("[+] Driver was loaded!");
	DriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = 0;
	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)process_creation_callback, FALSE);
	DBG_LOG("[+] PsSetCreateProcessNotifyRoutine(process_creation_notifyer, FALSE) returned %x", status);

    status = process_callback_handler_open_registration();
    DBG_LOG("[+] process_callback_handler_open_registration returned %x", status);

    status = process_callback_imageload_registration();
    DBG_LOG("[+] process_callback_imageload_registration returned %x", status);

    status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, (PVOID)thread_creation_callback);

    KeInitializeSpinLock(&GLOBS.spinlock);
    InitializeListHead(&GLOBS.process_list);

    initialize_internal_functions();

	return STATUS_SUCCESS;
}
```
