# Using internal Windows functions in your kernel driver

Just a small post this time, still working on detection mechanisms in my toy EDR. 

Sometimes you want to use internal Windows functions for your kernel driver, for whatever reason. I'll show how to use functions from ```ntoskrnl.exe```, but it is the same principle for any other function.

This isn't really my work, but I modified it a little for my use. Could be useful to some.


Locate ntoskrnl.exe-base by walking the imports of our current driver. If you are loading your driver via a vulnerable kernel driver, you can use the name of a known driver as your starting point instead, as all drivers will have it in their import table.

```C
PVOID locate_ntoskrnl_base(PDRIVER_OBJECT DriverObject) {
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    PLDR_DATA_TABLE_ENTRY first = entry;
    UNICODE_STRING ntoskrnl_str = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first) {
        if (RtlCompareUnicodeString(&entry->BaseDllName, &ntoskrnl_str, TRUE) == 0) {
            GLOBS.ntoskrnlsize = entry->SizeOfImage;
            GLOBS.ntoskrnladdress = entry->Dllbase;
            return;
        }
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
    return NULL;
}
```

Search functions taken shamelessly from this [Apex Legends cheat](https://github.com/TheCruZ/Apex_Legends_Driver_Cheat/blob/699250f6a9c0bc9c11d5e410742f253aeb884ca2/StrunderSv/StrunderSv/bypass.c).

```C
BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, PCHAR szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask) {
		if (*szMask == 'c' && *pData != *bMask) {
			return 0;
		}
	}
	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, PCHAR szMask)
{
	for (UINT64 i = 0; i < dwLen; i++) {
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask)) {
			return (UINT64)(dwAddress + i);
		}
	}

	return 0;
}

PVOID search_for_pattern(PVOID base_address, ULONG max_size, BYTE *bytemask, PCHAR szmask) {
	return (PVOID)FindPattern((UINT64)(ULONG_PTR)base_address, (UINT64)max_size, bytemask, szmask);
}
```

Find the internal function you want to use, for instance in IDA. I wanted to use ```PspGetContextThreadInternal```, which starts like in the below.
```
40 55                                         push    rbp
57                                            push    rdi
41 54                                         push    r12
41 56                                         push    r14
41 57                                         push    r15
48 81 EC F0 01 00 00                          sub     rsp, 1F0h
48 8D 6C 24 40                                lea     rbp, [rsp+40h]
48 89 9D F0 01 00 00                          mov     [rbp+1D0h+arg_10], rbx
48 8B 05 3D 46 DE FF                          mov     rax, cs:__security_cookie
48 33 C5                                      xor     rax, rbp
48 89 85 A8 01 00 00                          mov     [rbp+1D0h+var_28], rax
```
Copying out the bytes, we can search for it in ntoskrnl.exe. Beware, if you search outside the bounderies, you will crash. You might crash irregardless.

We can then find a specific function, specifying the initial bytes of it in the third argument below.

```C
locate_ntoskrnl_base(DriverObject);
PVOID PspGetContextThreadInternal_address = search_for_pattern(GLOBS.ntoskrnladdr, GLOBS.ntoskrnlsize, (UCHAR*)"\x40\x55\x57\x41\x54\x41\x56\x41\x57\x48\x81\xec\xf0\x01\x00", "ccccccccccccccc");
```

Until next time.
