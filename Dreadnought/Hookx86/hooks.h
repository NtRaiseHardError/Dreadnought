#pragma once
#ifndef __HOOKS_H__
#define __HOOKS_H__

#include <Windows.h>

#include "hookhelper.h"

NTSTATUS NTAPI HookedNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
NTSTATUS NTAPI HookedNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
//NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
//NTSTATUS NTAPI HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, SIZE_T *NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS NTAPI HookedNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
NTSTATUS NTAPI HookedNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER  SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
NTSTATUS NTAPI HookedNtAddAtom(PWCHAR AtomName, PRTL_ATOM Atom);
//NTSTATUS NTAPI HookedNtQueryInformationAtom(RTL_ATOM Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedLdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
NTSTATUS WINAPI HookedNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE  lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD StackZeroBits, DWORD SizeOfStackCommit, DWORD SizeOfstackReserve, CREATE_THREAD_INFO *ThreadInfo);
NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES   ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);
NTSTATUS NTAPI HookedNtQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved);
//NTSTATUS NTAPI HookedLdrGetProcedureAddressEx(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID *ProcedureAddress, ULONG Flags);
NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI HookedNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
HHOOK WINAPI HookedSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
HHOOK WINAPI HookedSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);

#endif // !__HOOKS_H__
