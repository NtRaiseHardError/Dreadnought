#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>

#include "static.h"
#include "Util.h"

// import functions
std::vector<std::string> importStrings = { "CreateProcessA", "CreateProcessW", "CreateProcessInternalA", "CreateProcessInternalW", "VirtualAllocEx", "WriteProcessMemory", 
										"GetThreadContext", "SetThreadContext", "Wow64GetThreadContext", "Wow64SetThreadContext", "ResumeThread", "NtCreateUserProcess", 
										"ZwCreateUserProcess", "NtGetContextThread", "NtGetContextThread", "NtSetContextThread", "ZwGetContextThread", "ZwSetContextThread", 
										"RtlCreateUserProcess", "RtlCreateUserProcess", "NtCreateUserProcess", "ZwCreateUserProcess", "NtResumeThread", "ZwResumeThread", 
										"NtUnmapViewOfSection", "ZwUnmapViewOfSection", "CreateToolhelp32Snapshot", "NtQuerySystemInformation",	/* SystemProcessInformation for CreateToolhelp32Snapshot */ 
										"Process32First", "Process32FirstW", "Process32Next", "Process32NextW", "OpenProcess", "NtOpenProcess", "ZwOpenProcess", "VirtualProctect", "VirtualProtectEx", 
										"NtProtectVirtualMemory", "ZwProtectVirtualMemory", "VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory", "VirtualAllocExNuma", "NtCreateSection", 
										"NtMapViewOfSection", "ZwMapViewOfSection", "GlobalAddAtomA", "GlobalAddAtomW", "NtAddAtom", "GlobalGetAtomNameA", "GlobalGetAtomNameW", 
										"NtQueryInformationAtom", "ZwQueryInformationAtom", "LoadLibraryA", "LoadLibraryexA", "LoadLibraryW", "LoadLibraryExW", "LdrLoadDll", 
										"CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",  "ZwCreateThreadEx", "NtCreateThread", "ZwCreateThread", "QueueUserAPC", 
										"NtQueueApcThread", "ZwQueueApcThread", "SetWindowsHookA", "SetWindowsHookW", "SetWindowsHookExA", "SetWindowsHookExW", "GetProcAddress",
										"LdrGetProcedureAddress", "LdrGetProcedureAddressEx", "OpenThread", "NtOpenThread", "ZwOpenThread" };

/*
* Map PE file into memory
*/
static bool memoryMapPayload(const LPVOID lpDest, const LPVOID lpPayload, const PIMAGE_DOS_HEADER pidh, const PIMAGE_NT_HEADERS pinh) {
	// copy section headers
	CopyMemory(lpDest, lpPayload, pinh->OptionalHeader.SizeOfHeaders);

	// copy each section individually at virtual address
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)lpPayload + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
		CopyMemory(((LPBYTE)lpDest + pish->VirtualAddress), ((LPBYTE)lpPayload + pish->PointerToRawData), pish->SizeOfRawData);
	}

	return true;
}

/*
* Walk the import table and fix the addresses
*/
static bool checkImportTable(const LPVOID lpBaseAddress, const PIMAGE_NT_HEADERS pinh, std::map<std::string, bool>& imports) {
	bool ret = false;
	// parse import table if size != 0
	if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		// https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)(lpBaseAddress)+pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
		while (pImportDescriptor->Name) {
			PIMAGE_THUNK_DATA nameRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress)+pImportDescriptor->Characteristics);
			PIMAGE_THUNK_DATA symbolRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress)+pImportDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA lpThunk = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress)+pImportDescriptor->FirstThunk);
			for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
				// fix addresses
				// check if import by ordinal
				if (!(nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG)) {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((DWORD)(lpBaseAddress)+nameRef->u1.AddressOfData);
					std::string importName((LPCSTR)(&thunkData->Name));
					for (std::map<std::string, bool>::iterator iter = imports.begin(); iter != imports.end(); ++iter) {
						if (!iter->first.compare(importName)) {
							iter->second = true;
							ret = true;
						}
					}
				}
			}
			pImportDescriptor++;
		}
	}

	return ret;
}

bool analyseImports(const std::vector<BYTE>& file) {
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)file.data();
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)(file.data() + pidh->e_lfanew);

	// check PE file
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE || pinh->Signature != IMAGE_NT_SIGNATURE) {
		::SetLastError(ERROR_BAD_EXE_FORMAT);
		return false;
	}

	// make map of import strings
	std::map<std::string, bool> imports;
	for (const auto s : importStrings)
		imports.insert({ s, false });

	// map payload to memory
	LPBYTE lpAddress = new BYTE[pinh->OptionalHeader.SizeOfImage];
	if (memoryMapPayload(lpAddress, (LPVOID)file.data(), pidh, pinh)) {
		// walk import table
		if (checkImportTable(lpAddress, pinh, imports)) {
			Util::debug<Util::WARNING>("Suspicious imports found:\n");
			for (const auto import : imports) {
				if (import.second)
					Util::debug<Util::MOREINFO>(import.first + "\n");
			}
		} else
			Util::debug<Util::INFO>("No suspicious imports found\n");
	}
	std::cout << "\n";

	delete lpAddress;

	return true;
}

bool stringSearch(const std::string haystack, std::map<std::string, bool>& imports) {
	// return true if strings found
	bool ret = false;

	// set into std::string
	for (std::map<std::string, bool>::iterator iter = imports.begin(); iter != imports.end(); ++iter) {
		if (haystack.find(iter->first) != std::string::npos) {
			iter->second = true;
			ret = true;
		}
	}

	// again for lowercase
	for (std::map<std::string, bool>::iterator iter = imports.begin(); iter != imports.end(); ++iter) {
		// check if string already found
		if (!iter->second) {
			std::string lowercase = iter->first;
			std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(), ::tolower);
			if (haystack.find(lowercase) != std::string::npos) {
				iter->second = true;
				ret = true;
			}
		}
	}

	return ret;
}

bool analyseStrings(const std::vector<BYTE>& file) {
	// set up import map
	std::map<std::string, bool> imports;
	for (const auto s : importStrings)
		imports.insert({ s, false });

	std::string haystack(file.data(), file.data() + file.size());
	if (stringSearch(haystack, imports)) {
		Util::debug<Util::WARNING>("Suspicious strings found:\n");
		for (const auto import : imports)
			if (import.second)
				Util::debug<Util::MOREINFO>(import.first + "\n");
	} else
		Util::debug<Util::INFO>("No suspicious strings found\n");

	std::cout << "\n";

	return true;
}