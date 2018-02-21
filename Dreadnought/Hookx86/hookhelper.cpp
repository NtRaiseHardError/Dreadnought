#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#include "hookhelper.h"
#include "hooks.h"
#include "Util.h"

#pragma comment(lib, "Shlwapi.lib")

fpNtQueryInformationThread fNtQueryInformationThread = nullptr;

fpNtCreateUserProcess fNtCreateUserProcess = nullptr;
fpNtUnmapViewOfSection fNtUnmapViewOfSection = nullptr;
fpNtAllocateVirtualMemory fNtAllocateVirtualMemory = nullptr;
fpNtWriteVirtualMemory fNtWriteVirtualMemory = nullptr;
fpNtGetContextThread fNtGetContextThread = nullptr;
fpNtSetContextThread fNtSetContextThread = nullptr;
fpNtResumeThread fNtResumeThread = nullptr;
fpNtQuerySystemInformation fNtQuerySystemInformation = nullptr;
fpNtProtectVirtualMemory fNtProtectVirtualMemory = nullptr;
fpNtCreateSection fNtCreateSection = nullptr;
fpNtMapViewOfSection fNtMapViewOfSection = nullptr;
fpNtAddAtom fNtAddAtom = nullptr;
fpNtQueryInformationAtom fNtQueryInformationAtom = nullptr;
fpLdrLoadDll fLdrLoadDll = nullptr;
fpNtCreateThreadEx fNtCreateThreadEx = nullptr;
fpNtCreateThread fNtCreateThread = nullptr;
fpNtQueueApcThread fNtQueueApcThread = nullptr;
fpLdrGetProcedureAddressEx fLdrGetProcedureAddressEx = nullptr;
fpNtOpenProcess fNtOpenProcess = nullptr;
fpNtOpenThread fNtOpenThread = nullptr;

std::map<std::string, LPBYTE> g_originalBytes;
std::map<INJECTION_TYPE, unsigned int> heuristic;
HMODULE g_hNtDll = nullptr;
DWORD g_dwMainThreadId = 0;

bool getMainThreadId(DWORD *pdwThreadId) {
	bool bResult = false;

	ULONG_PTR hModule = (ULONG_PTR)GetModuleHandle(nullptr);
	if (!hModule)
		return false;

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)hModule;
	if (!pidh)
		return false;

	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((ULONG_PTR)pidh + pidh->e_lfanew);
	if (!pinh)
		return false;

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);

	if (::Thread32First(hSnapshot, &te32)) {
		do {
			if (te32.th32OwnerProcessID != ::GetCurrentProcessId())
				continue;

			HANDLE hThreadHandle = ::OpenThread(THREAD_ALL_ACCESS, false, te32.th32ThreadID);

			if (!hThreadHandle)
				continue;

			ULONG len;
			ULONG_PTR nThreadStartAddress;
			fNtQueryInformationThread = (fpNtQueryInformationThread)::GetProcAddress(g_hNtDll, "NtQueryInformationThread");
			if (NT_SUCCESS(fNtQueryInformationThread(hThreadHandle, ThreadQuerySetWin32StartAddress, &nThreadStartAddress, sizeof(nThreadStartAddress), &len))) {
				if ((hModule + pinh->OptionalHeader.AddressOfEntryPoint) == nThreadStartAddress) {
					bResult = true;
					*pdwThreadId = te32.th32ThreadID;
				}
			}
			::CloseHandle(hThreadHandle);
		} while (::Thread32Next(hSnapshot, &te32) && bResult == false);
	}

	::CloseHandle(hSnapshot);

	return bResult;
}

void initialiseHooks() {
	//::Sleep(10000);

	//__asm int 3;
	Util::log<Util::INFO>("Initialising hooks...\n");
	// get dll handle
	g_hNtDll = ::GetModuleHandle(L"ntdll.dll");

	if (!g_hNtDll)
		Util::fatal("Failed to obtain DLL handles\n");

	// hook functions
	LPBYTE bytes = nullptr;
	fNtCreateUserProcess = (fpNtCreateUserProcess)::GetProcAddress(g_hNtDll, "ZwCreateUserProcess");
	if (!fNtCreateUserProcess)
		Util::fatal("Failed to obtain NtCreateUserProcess.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtCreateUserProcess, (DWORD)HookedNtCreateUserProcess);
	g_originalBytes.insert({ "NtCreateUserProcess", bytes });

	fNtUnmapViewOfSection = (fpNtUnmapViewOfSection)::GetProcAddress(g_hNtDll, "ZwUnmapViewOfSection");
	if (!fNtUnmapViewOfSection)
		Util::fatal("Failed to obtain NtUnmapViewOfSection.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtUnmapViewOfSection, (DWORD)HookedNtUnmapViewOfSection);
	g_originalBytes.insert({ "NtUnmapViewOfSection", bytes });

	//fNtAllocateVirtualMemory = (fpNtAllocateVirtualMemory)::GetProcAddress(g_hNtDll, "NtAllocateVirtualMemory");
	//if (!fNtAllocateVirtualMemory)
	//	Util::fatal("Failed to obtain NtAllocateVirtualMemory.\n");
	//bytes = Util::Memory::HookFunction((DWORD)fNtAllocateVirtualMemory, (DWORD)HookedNtAllocateVirtualMemory);
	//g_originalBytes.insert({ "NtAllocateVirtualMemory", bytes });

	fNtWriteVirtualMemory = (fpNtWriteVirtualMemory)::GetProcAddress(g_hNtDll, "NtWriteVirtualMemory");
	if (!fNtWriteVirtualMemory)
		Util::fatal("Failed to obtain NtWriteVirtualMemory.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtWriteVirtualMemory, (DWORD)HookedNtWriteVirtualMemory);
	g_originalBytes.insert({ "NtWriteVirtualMemory", bytes });

	fNtGetContextThread = (fpNtGetContextThread)::GetProcAddress(g_hNtDll, "NtGetContextThread");
	if (!fNtGetContextThread)
		Util::fatal("Failed to obtain NtGetContextThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtGetContextThread, (DWORD)HookedNtGetContextThread);
	g_originalBytes.insert({ "NtGetContextThread", bytes });

	fNtSetContextThread = (fpNtSetContextThread)::GetProcAddress(g_hNtDll, "NtSetContextThread");
	if (!fNtSetContextThread)
		Util::fatal("Failed to obtain NtSetContextThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtSetContextThread, (DWORD)HookedNtSetContextThread);
	g_originalBytes.insert({ "NtSetContextThread", bytes });

	fNtResumeThread = (fpNtResumeThread)::GetProcAddress(g_hNtDll, "NtResumeThread");
	if (!fNtResumeThread)
		Util::fatal("Failed to obtain NtResumeThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtResumeThread, (DWORD)HookedNtResumeThread);
	g_originalBytes.insert({ "NtResumeThread", bytes });

	fNtQuerySystemInformation = (fpNtQuerySystemInformation)::GetProcAddress(g_hNtDll, "NtQuerySystemInformation");
	if (!fNtQuerySystemInformation)
		Util::fatal("Failed to obtain NtQuerySystemInformation.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtQuerySystemInformation, (DWORD)HookedNtQuerySystemInformation);
	g_originalBytes.insert({ "NtQuerySystemInformation", bytes });

	//fNtProtectVirtualMemory = (fpNtProtectVirtualMemory)::GetProcAddress(g_hNtDll, "NtProtectVirtualMemory");
	//if (!fNtProtectVirtualMemory)
	//	Util::fatal("Failed to obtain NtProtectVirtualMemory.\n");
	//bytes = Util::Memory::HookFunction((DWORD)fNtProtectVirtualMemory, (DWORD)HookedNtProtectVirtualMemory);
	//g_originalBytes.insert({ "NtProtectVirtualMemory", bytes });

	fNtCreateSection = (fpNtCreateSection)::GetProcAddress(g_hNtDll, "NtCreateSection");
	if (!fNtCreateSection)
		Util::fatal("Failed to obtain NtCreateSection.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtCreateSection, (DWORD)HookedNtCreateSection);
	g_originalBytes.insert({ "NtCreateSection", bytes });

	fNtMapViewOfSection = (fpNtMapViewOfSection)::GetProcAddress(g_hNtDll, "NtMapViewOfSection");
	if (!fNtMapViewOfSection)
		Util::fatal("Failed to obtain NtMapViewOfSection.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtMapViewOfSection, (DWORD)HookedNtMapViewOfSection);
	g_originalBytes.insert({ "NtMapViewOfSection", bytes });

	//fNtAddAtom = (fpNtAddAtom)::GetProcAddress(g_hNtDll, "NtAddAtom");
	//if (!fNtAddAtom)
	//	Util::fatal("Failed to obtain NtAddAtom.\n");
	//bytes = Util::Memory::HookFunction((DWORD)fNtAddAtom, (DWORD)HookedNtAddAtom);
	//g_originalBytes.insert({ "NtAddAtom", bytes });

	//fNtQueryInformationAtom = (fpNtQueryInformationAtom)::GetProcAddress(g_hNtDll, "NtQueryInformationAtom");
	//if (!fNtQueryInformationAtom)
	//	Util::fatal("Failed to obtain NtQueryInformationAtom.\n");
	//bytes = Util::Memory::HookFunction((DWORD)fNtQueryInformationAtom, (DWORD)HookedNtQueryInformationAtom);
	//g_originalBytes.insert({ "NtQueryInformationAtom", bytes });

	fLdrLoadDll = (fpLdrLoadDll)::GetProcAddress(g_hNtDll, "LdrLoadDll");
	if (!fLdrLoadDll)
		Util::fatal("Failed to obtain LdrLoadDll.\n");
	bytes = Util::Memory::HookFunction((DWORD)fLdrLoadDll, (DWORD)HookedLdrLoadDll);
	g_originalBytes.insert({ "LdrLoadDll", bytes });

	fNtCreateThreadEx = (fpNtCreateThreadEx)::GetProcAddress(g_hNtDll, "NtCreateThreadEx");
	if (!fNtCreateThreadEx)
		Util::fatal("Failed to obtain NtCreateThreadEx.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtCreateThreadEx, (DWORD)HookedNtCreateThreadEx);
	g_originalBytes.insert({ "NtCreateThreadEx", bytes });

	fNtCreateThread = (fpNtCreateThread)::GetProcAddress(g_hNtDll, "NtCreateThread");
	if (!fNtCreateThread)
		Util::fatal("Failed to obtain NtCreateThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtCreateThread, (DWORD)HookedNtCreateThread);
	g_originalBytes.insert({ "NtCreateThread", bytes });

	fNtQueueApcThread = (fpNtQueueApcThread)::GetProcAddress(g_hNtDll, "NtQueueApcThread");
	if (!fNtQueueApcThread)
		Util::fatal("Failed to obtain NtQueueApcThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtQueueApcThread, (DWORD)HookedNtQueueApcThread);
	g_originalBytes.insert({ "NtQueueApcThread", bytes });

	fNtOpenProcess = (fpNtOpenProcess)::GetProcAddress(g_hNtDll, "NtOpenProcess");
	if (!fNtOpenProcess)
		Util::fatal("Failed to obtain NtOpenProcess.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtOpenProcess, (DWORD)HookedNtOpenProcess);
	g_originalBytes.insert({ "NtOpenProcess", bytes });

	fNtOpenThread = (fpNtOpenThread)::GetProcAddress(g_hNtDll, "NtOpenThread");
	if (!fNtOpenThread)
		Util::fatal("Failed to obtain NtOpenThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtOpenThread, (DWORD)HookedNtOpenThread);
	g_originalBytes.insert({ "NtOpenThread", bytes });

	//fLdrGetProcedureAddressEx = (fpLdrGetProcedureAddressEx)::GetProcAddress(g_hNtDll, "LdrGetProcedureAddressEx");
	//if (!fLdrGetProcedureAddressEx)
	//	Util::fatal("Failed to obtain LdrGetProcedureAddressEx.\n");
	//bytes = Util::Memory::HookFunction((DWORD)fLdrGetProcedureAddressEx, (DWORD)HookedLdrGetProcedureAddressEx);
	//g_originalBytes.insert({ "LdrGetProcedureAddressEx", bytes });

	bytes = Util::Memory::HookFunction((DWORD)::GetProcAddress(::GetModuleHandle(L"user32.dll"), "SetWindowsHookExA"), (DWORD)HookedSetWindowsHookExA);
	g_originalBytes.insert({ "SetWindowsHookExA", bytes });

	bytes = Util::Memory::HookFunction((DWORD)::GetProcAddress(::GetModuleHandle(L"user32.dll"), "SetWindowsHookExW"), (DWORD)HookedSetWindowsHookExW);
	g_originalBytes.insert({ "SetWindowsHookExW", bytes });

	// initialise heuristics
	std::map<INJECTION_TYPE, unsigned int> heuristic = { { PROCESS, 0 },{ DLL, 0 },{ CODE, 0 },
														{ ATOM_BOMB, 0 },{ SECTION, 0 },{ DOPPELGANGING, 0 } };

	writeHeuristicsToFile(heuristic);

	Util::log<Util::SUCCESS>("Success!\n\n");

	// get original thread to check in hooks
	getMainThreadId(&g_dwMainThreadId);

	// resume thread
	HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, false, g_dwMainThreadId);
	if (hThread)
		::ResumeThread(hThread);
	else
		Util::fatal("Failed to resume thread\n");
}

void getPeHeaders(LPVOID lpModule, PIMAGE_NT_HEADERS& pinh) {
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpModule;
	pinh = (PIMAGE_NT_HEADERS)((DWORD)lpModule + pidh->e_lfanew);
}

void virtualToRaw(std::vector<BYTE>& out, const std::vector<BYTE>& in) {
	// get headers
	PIMAGE_NT_HEADERS pinh;
	getPeHeaders((LPVOID)in.data(), pinh);

	// start raw size with size of headers
	DWORD dwSize = pinh->OptionalHeader.SizeOfHeaders;
	// get rest of raw size
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
		dwSize += pish->SizeOfRawData;
	}

	// now allocate raw vector
	std::vector<BYTE> raw(dwSize);

	// copy headers
	//raw.insert(raw.begin(), in.begin(), in.begin() + pinh->OptionalHeader.SizeOfHeaders);
	std::copy(in.data(), in.data() + pinh->OptionalHeader.SizeOfHeaders, raw.begin());
	// copy sections
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
		if (pish->SizeOfRawData > 0)
			std::copy(in.data() + pish->VirtualAddress, in.data() + pish->VirtualAddress + pish->SizeOfRawData, raw.begin() + pish->PointerToRawData);
	}

	out = raw;
}

bool dumpPe(const std::string fileName, LPVOID lpBuffer, const DWORD dwSize) {
	CHAR szPath[MAX_PATH + 1];
	::ZeroMemory(szPath, MAX_PATH + 1);
	::GetModuleFileNameA(nullptr, szPath, MAX_PATH);

	CHAR szTemp[MAX_PATH + 1];
	::StrCpyA(szTemp, ::PathFindFileNameA(szPath));
	::PathRemoveExtensionA(szTemp);

	std::string dumpPath = "Dumps\\";
	dumpPath += szTemp;

	::CreateDirectoryA(dumpPath.c_str(), nullptr);

	dumpPath += "\\";
	dumpPath += fileName;
	Util::log<Util::INFO>("Dumping to \"" + dumpPath + "\"...\n");

	HANDLE hFile = ::CreateFileA(dumpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
			Util::log<Util::FAILURE>("Failed to create dump file; error: " + std::to_string(::GetLastError()) + "\n\n");
		return false;
	}

	DWORD dwWritten = 0;
	if (!::WriteFile(hFile, lpBuffer, dwSize, &dwWritten, nullptr)) {
		::CloseHandle(hFile);
			Util::log<Util::FAILURE>("Failed to write to dump file; error: " + std::to_string(::GetLastError()) + "\n\n");
		return false;
	}

	::CloseHandle(hFile);
	Util::log<Util::SUCCESS>("Successfully dumped " + std::to_string(dwWritten) + " bytes to \"" + dumpPath + "\"\n\n");

	return true;
}

bool dumpRaw(const std::string fileName, const std::vector<BYTE>& data) {
	CHAR szPath[MAX_PATH + 1];
	::ZeroMemory(szPath, MAX_PATH + 1);
	::GetModuleFileNameA(nullptr, szPath, MAX_PATH);

	CHAR szTemp[MAX_PATH + 1];
	::StrCpyA(szTemp, ::PathFindFileNameA(szPath));
	::PathRemoveExtensionA(szTemp);

	std::string dumpPath = "Dumps\\";
	dumpPath += szTemp;

	::CreateDirectoryA(dumpPath.c_str(), nullptr);

	dumpPath += "\\";
	dumpPath += fileName;
	Util::log<Util::INFO>("Dumping to \"" + dumpPath + "\"...\n");

	HANDLE hFile = ::CreateFileA(dumpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		Util::log<Util::FAILURE>("Failed to create dump file; error: " + std::to_string(::GetLastError()) + "\n\n");
		return false;
	}

	DWORD dwWritten = 0;
	if (!::WriteFile(hFile, data.data(), data.size(), &dwWritten, nullptr)) {
		::CloseHandle(hFile);
		Util::log<Util::FAILURE>("Failed to write to dump file; error: " + std::to_string(::GetLastError()) + "\n\n");
		return false;
	}

	::CloseHandle(hFile);
	Util::log<Util::SUCCESS>("Successfully dumped " + std::to_string(dwWritten) + " bytes to \"" + dumpPath + "\"\n\n");

	return true;
}