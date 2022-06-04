# Writing a toy EPP/EDR for fun: Part 2

Just another quick post with two behaviour/anomaly detection methods for my toy EDR/EPP.

Disclaimer: This is just me trying (and failing) to code in the Windows kernel. Not trying to do anything new or unknown.

## Detecting threads starting in allocated memory

When running shellcode, an attacker may allocate the memory used to execute from. If this happens, and a thread is created, we can intercept the call to ```CreateThread```, and see if the memory executing is backed by a file on disk - i.e. if the memory type is MEM_IMAGE (0x1000000). We can just tack on this detection after our RWX threadstart detector.

```C

if (mbi.AllocationProtect == 0x40 || mbi.Protect == 0x40) {
    DBG_LOG("[!] Thread executing from RWX memory. Terminating process with PID %i", ProcessId);
    ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
    break;
}
if((mbi.Type & 0x1000000) != 0x1000000) {
    DBG_LOG("[!] Thread executing from memory not backed by file on disk. Terminating process with PID %i", ProcessId);
    ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
    reak;
}
```


## Detecting process hollowing

So when we get a callback, we'll use a bunch of heuristics to determine if the process is doing something we deem to be sketchy. In a way, the callbacks are our God-given (read: Microsoft-given) opportunity to inspect the process making the call. I don't know if that makes sense. Anyway, attackers have to obtain execution through SOME means right? So we denied the possibility of thread creation in RWX-regions in the previous post (though thread hijacking with ```[Get|Set]ThreadContext``` will still work). Above we deny starting threads in memory not backed by a module existing on disk. Here is a technique for detecting process hollowing, assuming that (a) we are able to intercept some suspicious action through our callbacks, and (b) the image of the process in question has been modified (and not a module). The second assumption is due to my laziness, we could check every module as well, but I'll leave that as an exercise for the reader.

So we do what I'll call "integrity checking" of the process running, checking whether the running code is the same as the executable from which it was created. I thought this would be pretty simple, but it was really difficult reading files into kernel memory without deadlocking stuff. In the end I made it work, though I have no clue why it works compared to my earlier attempts.

First, we must locate the process executable:

```C
PUNICODE_STRING process_name = NULL;
status = SeLocateProcessImageName(process, &process_name);
```

(This is the wrong way of doing it, but I don't care as it works very well using Windows 10. Please consult "Windows Kernel Programming" for the actual way).

Then, we must obtain a handle to the file using ```ZwCreateFile```, allocate kernel memory, and reading into it using ```ZwReadFile```. It should be simple, but there are some pitfalls. The flags set when opening the file appear to be very important, and the combination below seem to work for me. YMMV.

```C
IO_STATUS_BLOCK io_status_block = { 0 };
OBJECT_ATTRIBUTES file_attrs = { 0 };
InitializeObjectAttributes(&file_attrs, process_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

status = ZwCreateFile(&hFile, GENERIC_READ, &file_attrs, &io_status_block, NULL, FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING, 0, 0);

IO_STATUS_BLOCK io_status_blockv2 = { 0 };
FILE_STANDARD_INFORMATION file_info = { 0 };
status = ZwQueryInformationFile(hFile, &io_status_blockv2, &file_info, sizeof(file_info), FileStandardInformation);
...
ULONG sz = (ULONG)file_info.EndOfFile.QuadPart;
PVOID buf = ExAllocatePool(PagedPool, sz);
...
IO_STATUS_BLOCK io_status_blockv3 = { 0 };
status = ZwReadFile(hFile, NULL, NULL, NULL, &io_status_blockv3, buf, sz, NULL, NULL);
...
```

After we have read the contents of the file into memory, we can attach to the process we want to integrity check. This magically gives us access to that process' memory, and at the same time we still have access to the kernel buffer allocated previously. It is important that no matter what code path is taken, after we have called ```KeStackAttachProcess```, we also call ```KeUnstackDetachProcess```, otherwise blue screen is inevitable. It is also really important not to allocate kernel memory, or write to kernel memory while attached. I think.


```C
KAPC_STATE my_state = { 0 };
KeStackAttachProcess(process, &my_state);
```

Then we can begin comparing memory. We are interested in the actual instructions, which is (typically for Windows PEs anyways), stored in the ```.text```-segment. I guess this is not an assumption you want to make in production environments - it would probably be better to check all sections that are not flagged as writable on disk against those same sections in memory - but I will make that assumption anyway. From here on out its just normal PE parsing shenanigans.

```C
PIMAGE_DOS_HEADER file_dos_header = (PIMAGE_DOS_HEADER)buf;
PIMAGE_NT_HEADERS file_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)buf + file_dos_header->e_lfanew);

PIMAGE_DOS_HEADER file_dos_header = (PIMAGE_DOS_HEADER)buf;
PIMAGE_NT_HEADERS file_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)buf + file_dos_header->e_lfanew);

BOOLEAN edited = FALSE;
for (int i = 0; i < file_nt_header->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER file_sec_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(file_nt_header) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
    PIMAGE_SECTION_HEADER mem_sec_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(mem_nt_header) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
    if ((RtlCompareMemory(file_sec_header->Name, ".text", 5) == 5) && (RtlCompareMemory(mem_sec_header->Name, ".text", 5) == 5)) {
        char* file_raw = (char*)((DWORD_PTR)file_sec_header->PointerToRawData + (DWORD_PTR)buf);
        char* mem_raw = (char*)((DWORD_PTR)mem_sec_header->VirtualAddress + (DWORD_PTR)mem_base);
        SIZE_T diff = RtlCompareMemory((char*)((DWORD_PTR)file_sec_header->PointerToRawData + (DWORD_PTR)buf), (char*)((DWORD_PTR)mem_sec_header->VirtualAddress + (DWORD_PTR)mem_base), file_sec_header->SizeOfRawData);
        if (diff != file_sec_header->SizeOfRawData) {
            DBG_LOG("Number of differing bytes: %d", diff);
            edited = TRUE;
        }
        break;
    }
}
```

We can easily expand on this code to also include checking modules of the process in question in the same way. It could also be useful to walk the memory of the process.

Attackers can bypass these detection mechanisms in many ways. It should also be noted that it can only be called if other heuristics are unable to determine the legitimacy of a process, as it is relatively resource-intensive. Meaning if an attacker is able to fool the initial heuristics, they can avoid this detection method being ran against their code.

As usual, the complete code.
```C
BOOLEAN integrity_check_process(PEPROCESS process) {
    BOOLEAN return_value = TRUE;
    HANDLE hFile;
    NTSTATUS status;

    PUNICODE_STRING process_name = NULL;
    status = SeLocateProcessImageName(process, &process_name);

    if (!process_name || status != STATUS_SUCCESS) {
        goto ret;
    }

    IO_STATUS_BLOCK io_status_block = { 0 };
    OBJECT_ATTRIBUTES file_attrs = { 0 };
    InitializeObjectAttributes(&file_attrs, process_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hFile, GENERIC_READ, &file_attrs, &io_status_block, NULL, FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING, 0, 0);

    if (status != STATUS_SUCCESS) {
        DBG_LOG("[-] ZwCreateFile failed with status %x", status);
        goto free_process_ret;
    }

    IO_STATUS_BLOCK io_status_blockv2 = { 0 };
    FILE_STANDARD_INFORMATION file_info = { 0 };
    status = ZwQueryInformationFile(hFile, &io_status_blockv2, &file_info, sizeof(file_info), FileStandardInformation);

    if (status != STATUS_SUCCESS) {
        DBG_LOG("[-] ZwQueryInformationFile failed with status %x", status);
        goto close_file_ret;
    }

    ULONG sz = (ULONG)file_info.EndOfFile.QuadPart;
    PVOID buf = ExAllocatePool(PagedPool, sz);

    if (!buf) {
        goto close_file_ret;
    }

    IO_STATUS_BLOCK io_status_blockv3 = { 0 };
    KIRQL k = KeGetCurrentIrql();
    if (k != PASSIVE_LEVEL) {
        DBG_LOG("[-] KIRQL is not PASSIVE_LEVEL.");
        goto free_buffer_ret;
    }
    
    status = ZwReadFile(hFile, NULL, NULL, NULL, &io_status_blockv3, buf, sz, NULL, NULL);

    if (status != STATUS_SUCCESS) {
        DBG_LOG("[-] ZwReadFile failed with status %x", status);
        goto free_buffer_ret;
    }

    PIMAGE_DOS_HEADER file_dos_header = (PIMAGE_DOS_HEADER)buf;
    PIMAGE_NT_HEADERS file_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)buf + file_dos_header->e_lfanew);

    if (file_dos_header->e_magic != 0x5a4d) {
        //Error handling
    }

    if (file_nt_header->Signature != 0x4550) {
        //Error handling
    }

    KAPC_STATE my_state = { 0 };
    KeStackAttachProcess(process, &my_state);

    PVOID mem_base = PsGetProcessSectionBaseAddress(process);
    PIMAGE_DOS_HEADER mem_dos_header = (PIMAGE_DOS_HEADER)mem_base;
    PIMAGE_NT_HEADERS mem_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)buf + mem_dos_header->e_lfanew);
    if (mem_dos_header->e_magic != 0x5a4d) {
        //Error handling
    }

    if (mem_nt_header->Signature != 0x4550) {
        //Error handling
    }

    BOOLEAN edited = FALSE;
    for (int i = 0; i < file_nt_header->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER file_sec_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(file_nt_header) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        PIMAGE_SECTION_HEADER mem_sec_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(mem_nt_header) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if ((RtlCompareMemory(file_sec_header->Name, ".text", 5) == 5) && (RtlCompareMemory(mem_sec_header->Name, ".text", 5) == 5)) {
            char* file_raw = (char*)((DWORD_PTR)file_sec_header->PointerToRawData + (DWORD_PTR)buf);
            char* mem_raw = (char*)((DWORD_PTR)mem_sec_header->VirtualAddress + (DWORD_PTR)mem_base);
            SIZE_T diff = RtlCompareMemory((char*)((DWORD_PTR)file_sec_header->PointerToRawData + (DWORD_PTR)buf), (char*)((DWORD_PTR)mem_sec_header->VirtualAddress + (DWORD_PTR)mem_base), file_sec_header->SizeOfRawData);
            if (diff != file_sec_header->SizeOfRawData) {
                DBG_LOG("Differing bytes: %d", diff);
                edited = TRUE;
            }
            break;
        }
    }
    
    if (edited) {
        DBG_LOG("[!] Process with PID %i (%wZ) was edited.", PsGetProcessId(process), process_name);
        return_value = FALSE;
    }

    KeUnstackDetachProcess(&my_state);

free_buffer_ret:
    ExFreePool(buf);
close_file_ret:
    ZwClose(hFile);
free_process_ret:
    ExFreePool(process_name);
ret:
    return return_value;
}
```
