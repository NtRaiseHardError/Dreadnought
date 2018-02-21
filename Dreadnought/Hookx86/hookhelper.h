#pragma once
#ifndef __HOOKHELPER_H__
#define __HOOKHELPER_H__

#include <vector>
#include <map>
#include <Windows.h>

#include "definitions.h"
#include "heuristics.h"

typedef
NTSTATUS
(NTAPI *fpNtCreateUserProcess)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
	ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
	PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
	PPS_CREATE_INFO CreateInfo,
	PPS_ATTRIBUTE_LIST AttributeList
);

typedef
NTSTATUS
(NTAPI *fpNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

typedef
NTSTATUS
(NTAPI *fpNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

typedef
NTSTATUS
(NTAPI *fpNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
);

typedef
NTSTATUS
(NTAPI *fpNtGetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT Context
);

typedef
NTSTATUS
(NTAPI *fpNtSetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT Context
);

typedef
NTSTATUS
(NTAPI *fpNtResumeThread)(
	HANDLE ThreadHandle,
	PULONG SuspendCount
);

typedef LONG THREADINFOCLASS;
typedef
NTSTATUS
(NTAPI *fpNtQueryInformationThread)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
);

typedef
NTSTATUS
(WINAPI *fpNtQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);

typedef
NTSTATUS
(NTAPI *fpNtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID *BaseAddress,
	_In_ SIZE_T *NumberOfBytesToProtect,
	_In_ ULONG NewAccessProtection,
	_Out_ PULONG OldAccessProtection
);

typedef
NTSTATUS
(NTAPI *fpNtCreateSection)(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);

typedef
NTSTATUS
(NTAPI *fpNtMapViewOfSection)(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);

typedef
NTSTATUS
(NTAPI *fpNtAddAtom)(
	IN  PWCHAR              AtomName,
	OUT PRTL_ATOM           Atom
);

typedef
NTSTATUS
(NTAPI *fpNtQueryInformationAtom)(
	IN RTL_ATOM             Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID               AtomInformation,
	IN ULONG                AtomInformationLength,
	OUT PULONG              ReturnLength
);

typedef
NTSTATUS
(NTAPI *fpLdrLoadDll)(
	IN PWCHAR               PathToFile,
	IN ULONG                Flags,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle
);

typedef
NTSTATUS
(WINAPI *fpNtCreateThreadEx)(
	OUT PHANDLE                 hThread,
	IN  ACCESS_MASK             DesiredAccess,
	IN  POBJECT_ATTRIBUTES      ObjectAttributes,
	IN  HANDLE                  ProcessHandle,
	IN  LPTHREAD_START_ROUTINE  lpStartAddress,
	IN  LPVOID                  lpParameter,
	IN  BOOL                    CreateSuspended,
	IN  DWORD                   StackZeroBits,
	IN  DWORD                   SizeOfStackCommit,
	IN  DWORD                   SizeOfstackReserve,
	OUT CREATE_THREAD_INFO      *ThreadInfo         // guesswork
);

typedef
NTSTATUS
(NTAPI *fpNtCreateThread)(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended
);

typedef
NTSTATUS
(NTAPI *fpNtQueueApcThread)(
	IN HANDLE               ThreadHandle,
	IN PIO_APC_ROUTINE      ApcRoutine,
	IN PVOID                ApcRoutineContext,
	IN PIO_STATUS_BLOCK     ApcStatusBlock,
	IN ULONG                ApcReserved
);

typedef
NTSTATUS
(NTAPI *fpLdrGetProcedureAddressEx)(
    _In_ PVOID DllHandle,
    _In_opt_ PANSI_STRING ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID *ProcedureAddress,
    _In_ ULONG Flags
);

typedef
NTSTATUS 
(NTAPI *fpNtOpenProcess)(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

typedef
NTSTATUS
(NTAPI *fpNtOpenThread)(
	_Out_ PHANDLE            ThreadHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  PCLIENT_ID         ClientId
);

extern fpNtQueryInformationThread fNtQueryInformationThread;
extern fpNtCreateUserProcess fNtCreateUserProcess;
extern fpNtUnmapViewOfSection fNtUnmapViewOfSection;
extern fpNtAllocateVirtualMemory fNtAllocateVirtualMemory;
extern fpNtWriteVirtualMemory fNtWriteVirtualMemory;
extern fpNtGetContextThread fNtGetContextThread;
extern fpNtSetContextThread fNtSetContextThread;
extern fpNtResumeThread fNtResumeThread;
extern fpNtQuerySystemInformation fNtQuerySystemInformation;
extern fpNtProtectVirtualMemory fNtProtectVirtualMemory;
extern fpNtCreateSection fNtCreateSection;
extern fpNtMapViewOfSection fNtMapViewOfSection;
extern fpNtAddAtom fNtAddAtom;
extern fpNtQueryInformationAtom fNtQueryInformationAtom;
extern fpLdrLoadDll fLdrLoadDll;
extern fpNtCreateThreadEx fNtCreateThreadEx;
extern fpNtCreateThread fNtCreateThread;
extern fpNtQueueApcThread fNtQueueApcThread;
extern fpLdrGetProcedureAddressEx fLdrGetProcedureAddressEx;
extern fpNtOpenProcess fNtOpenProcess;
extern fpNtOpenThread fNtOpenThread;

extern std::map<std::string, LPBYTE> g_originalBytes;
extern HMODULE g_hNtDll;
extern DWORD g_dwMainThreadId;

void initialiseHooks();
void getPeHeaders(LPVOID lpModule, PIMAGE_NT_HEADERS& pinh);
void virtualToRaw(std::vector<BYTE>& out, const std::vector<BYTE>& in);
bool dumpPe(const std::string fileName, LPVOID lpBuffer, const DWORD dwSize);
bool dumpRaw(const std::string fileName, const std::vector<BYTE>& data);

#endif // !__HOOKHELPER_H__
