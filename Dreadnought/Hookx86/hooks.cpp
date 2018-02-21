#include <locale>
#include <codecvt>

#include "hooks.h"
#include "Util.h"

LPWORD lpAtom;
HANDLE g_hProcess = nullptr;
DWORD g_dwProcessId = 0;
DWORD g_dwImageBase = 0;

NTSTATUS NTAPI HookedNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtCreateUserProcess!\n");
		
		//setup converter
		using convert_type = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type, wchar_t> converter;
		// convert to multibyte
		std::string imagePath = converter.to_bytes(std::wstring(ProcessParameters->ImagePathName.Buffer));
		std::string commandLine = converter.to_bytes(std::wstring(ProcessParameters->CommandLine.Buffer));
		std::string currDir = converter.to_bytes(std::wstring(ProcessParameters->CurrentDirectoryPath.Buffer));

		Util::log<Util::MOREINFO>("Image path name: " + imagePath + "\n");
		Util::log<Util::MOREINFO>("Command line: " + commandLine + "\n");
		Util::log<Util::MOREINFO>("Current directory path" + currDir + "\n");

		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::PROCESS)->second++;
		heuristic.find(INJECTION_TYPE::DLL)->second++;
		writeHeuristicsToFile(heuristic);
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtCreateUserProcess, g_originalBytes.find("NtCreateUserProcess")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtCreateUserProcess")->second;

	// call original function
	NTSTATUS ret = ::fNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		if (NT_SUCCESS(ret)) {
			g_dwProcessId = ::GetProcessId(*ProcessHandle);
			g_hProcess = *ProcessHandle;
			Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(g_dwProcessId) + "\n");
			Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(::GetThreadId(*ThreadHandle)) + "\n\n");
		}
	}

	// rehook function
	g_originalBytes.find("NtCreateUserProcess")->second = Util::Memory::HookFunction((DWORD)fNtCreateUserProcess, (DWORD)HookedNtCreateUserProcess);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		if (ProcessHandle != ::GetCurrentProcess()) {
			Util::log<Util::SUCCESS>("Hooked NtUnmapViewOfSection!\n");
			// save process id
			DWORD dwProcessId = ::GetProcessId(ProcessHandle);
			Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(dwProcessId) + "\n");
			// save base address
			g_dwImageBase = (DWORD)BaseAddress;
			Util::log<Util::MOREINFO>("Base address: " + Util::decToHexString<DWORD>((DWORD)BaseAddress) + "\n\n");

			readHeuristicsFromFile(heuristic);
			heuristic.find(INJECTION_TYPE::PROCESS)->second++;
			heuristic.find(INJECTION_TYPE::SECTION)->second++;
			writeHeuristicsToFile(heuristic);
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtUnmapViewOfSection, g_originalBytes.find("NtUnmapViewOfSection")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtUnmapViewOfSection")->second;

	// call original function
	NTSTATUS ret = fNtUnmapViewOfSection(ProcessHandle, BaseAddress);

	// rehook function
	g_originalBytes.find("NtUnmapViewOfSection")->second = Util::Memory::HookFunction((DWORD)fNtUnmapViewOfSection, (DWORD)HookedNtUnmapViewOfSection);

	// return original call value
	return ret;	
}

// problems with this
//NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
//	if (::GetCurrentThreadId() == g_dwThreadId) {
//		//Util::log<Util::PLUS>("Hooked NtAllocateVirtualMemory!\n";
//		//DWORD dwProcessId = ::GetProcessId(ProcessHandle);
//		//Util::log<Util::MOREINFO>("Process ID: " + dwProcessId + ")\n";
//		//Util::log<Util::MOREINFO>("Base address: " + ::std::hex + (DWORD)BaseAddress + " | Region size: " + *RegionSize + "\n";
//
//		//// format protection value
//		//std::vector<std::string> protectionTypes;
//		//if (Protect & PAGE_NOACCESS) protectionTypes.push_back("PAGE_NOACCESS");
//		//if (Protect & PAGE_READONLY) protectionTypes.push_back("PAGE_READONLY");
//		//if (Protect & PAGE_READWRITE) protectionTypes.push_back("PAGE_READWRITE");
//		//if (Protect & PAGE_EXECUTE) protectionTypes.push_back("PAGE_EXECUTE");
//		//if (Protect & PAGE_EXECUTE_READ) protectionTypes.push_back("PAGE_EXECUTE_READ");
//		//if (Protect & PAGE_EXECUTE_READWRITE) protectionTypes.push_back("PAGE_EXECUTE_READWRITE");
//		//if (Protect & PAGE_EXECUTE_WRITECOPY) protectionTypes.push_back("PAGE_EXECUTE_WRITECOPY");
//
//		//std::string protections;
//		//for (int i = 0; i < protectionTypes.size(); i++) {
//		//	protections += protectionTypes.at(i);
//
//		//	if (i != protectionTypes.size() - 1)
//		//		protections += " | ";
//		//}
//
//		//Util::log<Util::MOREINFO>("Protection type: " + protections + " (" + std::hex + Protect + ")\n\n";
//	}
//
//	// unhook to call function
//	Util::Memory::UnhookFunction((DWORD)fNtAllocateVirtualMemory, g_originalBytes.find("NtAllocateVirtualMemory")->second);
//	// free original bytes after use
//	delete g_originalBytes.find("NtAllocateVirtualMemory")->second;
//
//	// call original function
//	NTSTATUS ret = fNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
//
//	// rehook function
//	g_originalBytes.find("NtAllocateVirtualMemory")->second = Util::Memory::HookFunction((DWORD)fNtAllocateVirtualMemory, (DWORD)HookedNtAllocateVirtualMemory);
//
//	// return original call value
//	return ret;
//}

NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		static unsigned int fileCount = 0;
		Util::log<Util::SUCCESS>("Hooked NtWriteVirtualMemory!\n");
		DWORD dwProcessId = ::GetProcessId(ProcessHandle);
		Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(dwProcessId) + "\n");
		Util::log<Util::MOREINFO>("Base address: " + Util::decToHexString<DWORD>((DWORD)BaseAddress) + "\n");
		Util::log<Util::MOREINFO>("Buffer at " + Util::decToHexString<DWORD>((DWORD)Buffer) + " | Size: " + Util::decToHexString<DWORD>(NumberOfBytesToWrite) + "\n\n");
		
		// only external code injection
		if (g_hProcess && g_hProcess != ::GetCurrentProcess() && Buffer && NumberOfBytesToWrite) {
			readHeuristicsFromFile(heuristic);
			heuristic.find(INJECTION_TYPE::PROCESS)->second++;
			heuristic.find(INJECTION_TYPE::CODE)->second++;
			heuristic.find(INJECTION_TYPE::DLL)->second++;
			writeHeuristicsToFile(heuristic);

			std::vector<BYTE> data(NumberOfBytesToWrite);
			std::copy((LPBYTE)Buffer, (LPBYTE)Buffer + NumberOfBytesToWrite, data.begin());
			dumpRaw("NtWriteVirtualMemory" + std::to_string(fileCount) + "_dump.bin", data);
			fileCount++;
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtWriteVirtualMemory, g_originalBytes.find("NtWriteVirtualMemory")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtWriteVirtualMemory")->second;

	// call original function
	NTSTATUS ret = fNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

	// rehook function
	g_originalBytes.find("NtWriteVirtualMemory")->second = Util::Memory::HookFunction((DWORD)fNtWriteVirtualMemory, (DWORD)HookedNtWriteVirtualMemory);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtGetContextThread!\n");
		DWORD dwThreadId = ::GetThreadId(ThreadHandle);
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(dwThreadId) + "\n\n");

		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::PROCESS)->second += 2;	// heavier bias?
		heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
		writeHeuristicsToFile(heuristic);
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtGetContextThread, g_originalBytes.find("NtGetContextThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtGetContextThread")->second;

	// call original function
	NTSTATUS ret = fNtGetContextThread(ThreadHandle, Context);

	// rehook function
	g_originalBytes.find("NtGetContextThread")->second = Util::Memory::HookFunction((DWORD)fNtGetContextThread, (DWORD)HookedNtGetContextThread);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtSetContextThread!\n");
		DWORD dwThreadId = ::GetThreadId(ThreadHandle);
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(dwThreadId) + "\n\n");

		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::PROCESS)->second++;
		heuristic.find(INJECTION_TYPE::SECTION)->second++;
		heuristic.find(INJECTION_TYPE::CODE)->second++;
		heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
		writeHeuristicsToFile(heuristic);		
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtSetContextThread, g_originalBytes.find("NtSetContextThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtSetContextThread")->second;

	// call original function
	NTSTATUS ret = fNtSetContextThread(ThreadHandle, Context);

	// rehook function
	g_originalBytes.find("NtSetContextThread")->second = Util::Memory::HookFunction((DWORD)fNtSetContextThread, (DWORD)HookedNtSetContextThread);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtResumeThread!\n");
		DWORD dwThreadId = ::GetThreadId(ThreadHandle);
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(dwThreadId) + "\n");

		readHeuristicsFromFile(heuristic);
		// check if atom bombing is in progress
		if (heuristic.find(INJECTION_TYPE::PROCESS)->second > heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second) {
			// open process
			HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS /*PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_OPERATION*/, false, g_dwProcessId);
			if (!hProcess)
				Util::fatal("Failed to open process ID " + Util::decToHexString<DWORD>(g_dwProcessId) + "\n");

			Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(g_dwProcessId) + "\n\n");

			// TODO more reliable way of getting address space of code?

			// check remote shellcode or runpe
			//readHeuristicsFromFile(heuristic);
			if (heuristic.find(INJECTION_TYPE::PROCESS)->second || heuristic.find(INJECTION_TYPE::SECTION)->second) {
				// dump PE file

				// get image size of child process
				DWORD dwRead = 0;
				std::vector<BYTE> buffer(0x200);	// should be enough for PE headers
				if (::ReadProcessMemory(hProcess, (LPVOID)g_dwImageBase, &buffer[0], 0x200, &dwRead)) {
					Util::log<Util::INFO>("Heuristics detected: " + getInjectionTypeString(getHeighestHeuristicKey(heuristic)) + "\n");
					// check if MZ header
					if (buffer.at(0) == 'M' && buffer.at(1) == 'Z') {
						PIMAGE_NT_HEADERS pinh;
						getPeHeaders(buffer.data(), pinh);
						DWORD dwSizeOfImage = pinh->OptionalHeader.SizeOfImage;

						// explicitly unprotect region
						DWORD flProtect = 0;
						::VirtualProtectEx(hProcess, (LPVOID)g_dwImageBase, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &flProtect);

						// read from image base until region size
						dwRead = 0;
						std::vector<BYTE> pe(dwSizeOfImage);
						if (!::ReadProcessMemory(hProcess, (LPVOID)g_dwImageBase, &pe[0], dwSizeOfImage, &dwRead))
							Util::log<Util::FAILURE>("Failed to read process ID " + Util::decToHexString<DWORD>(g_dwProcessId) + " error: " + Util::decToHexString<DWORD>(::GetLastError()) + "\n");

						std::vector<BYTE> raw;
						virtualToRaw(raw, pe);

						Util::log<Util::INFO>("Dumping [" + Util::decToHexString<DWORD>(raw.size()) + "] bytes at base address [" + Util::decToHexString<DWORD>(g_dwImageBase) + "] from process ID [" + Util::decToHexString<DWORD>(g_dwProcessId) + "]...\n");
						dumpPe("NtResumeThread_dump.bin", raw.data(), raw.size());

						// terminate process
						Util::log<Util::INFO>("Terminating child process...\n");
						::TerminateProcess(hProcess, 0);
						::CloseHandle(hProcess);

						Util::log<Util::INFO>("Terminating main process...\n\n");
						::ExitProcess(0);
					} else
						Util::log<Util::FAILURE>("Failed to obtain image size of child process ID " + Util::decToHexString<DWORD>(g_dwProcessId) + " error: " + Util::decToHexString<DWORD>(::GetLastError()) + "\n\n");
				} else {
					Util::log<Util::INFO>("Heuristics detected: " + getInjectionTypeString(getHeighestHeuristicKey(heuristic)) + "\n\n");
					// dump section

					// terminate process
					//Util::log<Util::INFO>("Terminating child process...\n");
					//::TerminateProcess(hProcess, 0);
					//::CloseHandle(hProcess);

					//Util::log<Util::INFO>("Terminating main process...\n");
					//::ExitProcess(0);
				}
			}
			Util::log<Util::INFO>("Blocking call...\n\n");
			return 3;	// NT_ERROR
		} else if (getHeighestHeuristicKey(heuristic) == INJECTION_TYPE::ATOM_BOMB) {
			Util::log<Util::INFO>("Detected atom bombing!\n\n");
			//Util::log<Util::INFO>("Blocking call...\n\n");
			//return 3;	// NT_ERROR
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtResumeThread, g_originalBytes.find("NtResumeThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtResumeThread")->second;

	// call original function
	NTSTATUS ret = fNtResumeThread(ThreadHandle, SuspendCount);

	// rehook function
	g_originalBytes.find("NtResumeThread")->second = Util::Memory::HookFunction((DWORD)fNtResumeThread, (DWORD)HookedNtResumeThread);

	// return original call value
	return ret;
}

// CreateToolhelp32Snapshot w/ SystemProcessInformation
NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		if (SystemInformationClass == SystemProcessInformation) {
			// TODO 

			readHeuristicsFromFile(heuristic);
			heuristic.find(INJECTION_TYPE::DLL)->second++;
			heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
			writeHeuristicsToFile(heuristic);
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtQuerySystemInformation, g_originalBytes.find("NtQuerySystemInformation")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtQuerySystemInformation")->second;

	// call original function
	NTSTATUS ret = fNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	// rehook function
	g_originalBytes.find("NtQuerySystemInformation")->second = Util::Memory::HookFunction((DWORD)fNtQuerySystemInformation, (DWORD)HookedNtQuerySystemInformation);

	// return original call value
	return ret;
}

//NTSTATUS NTAPI HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, SIZE_T *NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
//	if (::GetCurrentThreadId() == g_dwMainThreadId) {
//
//	}
//
//	// unhook to call function
//	Util::Memory::UnhookFunction((DWORD)fNtProtectVirtualMemory, g_originalBytes.find("NtProtectVirtualMemory")->second);
//	// free original bytes after use
//	delete g_originalBytes.find("NtProtectVirtualMemory")->second;
//
//	// call original function
//	NTSTATUS ret = fNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
//
//	// rehook function
//	g_originalBytes.find("NtProtectVirtualMemory")->second = Util::Memory::HookFunction((DWORD)fNtProtectVirtualMemory, (DWORD)HookedNtProtectVirtualMemory);
//
//	// return original call value
//	return ret;
//}

NTSTATUS NTAPI HookedNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtCreateSection!\n");
		Util::log<Util::MOREINFO>("Desired access: " + Util::decToHexString<DWORD>((DWORD)DesiredAccess) + "\n");
		if (MaximumSize)
			Util::log<Util::MOREINFO>("Maximum size: Low: " + Util::decToHexString<DWORD>(MaximumSize->LowPart) + "; High: " + Util::decToHexString<DWORD>(MaximumSize->HighPart) + "\n");
		Util::log<Util::MOREINFO>("Section page protection: " + Util::decToHexString<DWORD>(SectionPageProtection) + "\n\n");

		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::SECTION)->second++;
		writeHeuristicsToFile(heuristic);
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtCreateSection, g_originalBytes.find("NtCreateSection")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtCreateSection")->second;

	// call original function
	NTSTATUS ret = fNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

	// rehook function
	g_originalBytes.find("NtCreateSection")->second = Util::Memory::HookFunction((DWORD)fNtCreateSection, (DWORD)HookedNtCreateSection);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		// external processes only
		if (ProcessHandle != ::GetCurrentProcess()) {
			Util::log<Util::SUCCESS>("Hooked NtMapViewOfSection!\n");
			Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(::GetProcessId(ProcessHandle)) + "\n");
			if (BaseAddress)
				Util::log<Util::MOREINFO>("Base address: " + Util::decToHexString<DWORD>(*(LPDWORD)BaseAddress) + "\n");
			Util::log<Util::MOREINFO>("Commit size: " + Util::decToHexString<DWORD>(CommitSize) + "\n");
			Util::log<Util::MOREINFO>("Protection: " + Util::decToHexString<DWORD>(Win32Protect) + "\n\n");
			
			readHeuristicsFromFile(heuristic);
			heuristic.find(INJECTION_TYPE::SECTION)->second++;
			writeHeuristicsToFile(heuristic);
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtMapViewOfSection, g_originalBytes.find("NtMapViewOfSection")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtMapViewOfSection")->second;

	// call original function
	NTSTATUS ret = fNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

	// rehook function
	g_originalBytes.find("NtMapViewOfSection")->second = Util::Memory::HookFunction((DWORD)fNtMapViewOfSection, (DWORD)HookedNtMapViewOfSection);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtAddAtom(PWCHAR AtomName, PRTL_ATOM Atom) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		static unsigned int fileCount = 0;

		Util::log<Util::SUCCESS>("Hooked NtAddAtom!\n");
		
		// check if wide string atom name
		std::wstring atom = std::wstring(AtomName);
		INT flags = IS_TEXT_UNICODE_NULL_BYTES | IS_TEXT_UNICODE_ODD_LENGTH;
		if (::IsTextUnicode(AtomName, atom.length(), &flags) && flags == 1) {
			//setup converter
			using convert_type = std::codecvt_utf8<wchar_t>;
			std::wstring_convert<convert_type, wchar_t> converter;

			Util::log<Util::MOREINFO>("Attempting to dump atom name...\n");

			BYTE const *p = reinterpret_cast<BYTE const *>(&atom[0]);
			std::size_t size = atom.size() * sizeof(atom.front());
			//dumpRaw("NtAddAtom" + std::to_string(fileCount) + "_dump.bin", std::vector<BYTE>(p, p + size));
			fileCount++;
		} else {
			Util::log<Util::MOREINFO>("Attempting to dump atom name...\n");

			std::string atomName = std::string((LPSTR)AtomName);
			Util::log<Util::MOREINFO>("Atom name: " + atomName);
			//dumpRaw("NtAddAtom" + std::to_string(fileCount) + "_dump.bin", std::vector<BYTE>(atomName.begin(), atomName.end()));
			fileCount++;
		}

		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::DLL)->second++;
		heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
		writeHeuristicsToFile(heuristic);

		// check if atom bombing is in progress
		if (!heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second) {
			Util::log<Util::INFO>("Blocking call...\n\n");
			return 3;	// NT_ERROR
		} else {
			if (lpAtom) delete lpAtom;
			lpAtom = new WORD(::GlobalAddAtom(AtomName));
			Atom = lpAtom;
			return 0;
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtAddAtom, g_originalBytes.find("NtAddAtom")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtAddAtom")->second;

	// call original function
	NTSTATUS ret = fNtAddAtom(AtomName, Atom);

	// rehook function
	g_originalBytes.find("NtAddAtom")->second = Util::Memory::HookFunction((DWORD)fNtAddAtom, (DWORD)HookedNtAddAtom);

	// return original call value
	return ret;
}

//NTSTATUS NTAPI HookedNtQueryInformationAtom(RTL_ATOM Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength) {
//	if (::GetCurrentThreadId() == g_dwMainThreadId) {
//
//		readHeuristicsFromFile(heuristic);
//		heuristic.find(INJECTION_TYPE::DLL)->second++;
//		writeHeuristicsToFile(heuristic);
//	}
//
//	// unhook to call function
//	Util::Memory::UnhookFunction((DWORD)fNtQueryInformationAtom, g_originalBytes.find("NtQueryInformationAtom")->second);
//	// free original bytes after use
//	delete g_originalBytes.find("NtQueryInformationAtom")->second;
//
//	// call original function
//	NTSTATUS ret = fNtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
//
//	// rehook function
//	g_originalBytes.find("NtQueryInformationAtom")->second = Util::Memory::HookFunction((DWORD)fNtQueryInformationAtom, (DWORD)HookedNtQueryInformationAtom);
//
//	// return original call value
//	return ret;
//}

NTSTATUS NTAPI HookedLdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		//setup converter
		using convert_type = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type, wchar_t> converter;
		// convert to multibyte
		std::string pathToFile;
		if (PathToFile)
			pathToFile = converter.to_bytes(std::wstring(PathToFile));
		std::string moduleFileName = converter.to_bytes(std::wstring(ModuleFileName->Buffer));

		// get system path
		CHAR szPath[MAX_PATH + 1];
		::ZeroMemory(szPath, MAX_PATH + 1);
		::GetSystemDirectoryA(szPath, MAX_PATH);
		std::string systemPath = szPath;

		// parse load order paths and get application-loaded path (first path)
		std::string delimiter = ";";
		size_t pos = 0;
		std::string firstPath = pathToFile;
		if ((pos = pathToFile.find(delimiter)) != std::string::npos)
			firstPath = pathToFile.substr(0, pos);

		// skip if system DLL
		if (!firstPath.empty() && firstPath.find(systemPath) == std::string::npos) {
			Util::log<Util::SUCCESS>("Hooked LdrLoadDll!\n");
			Util::log<Util::MOREINFO>("Path to file: " + firstPath + "\n");
			Util::log<Util::MOREINFO>("Module file name: " + moduleFileName + "\n\n");

			//readHeuristicsFromFile(heuristic);
			//heuristic.find(INJECTION_TYPE::DLL)->second++;
			//heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
			//writeHeuristicsToFile(heuristic);
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fLdrLoadDll, g_originalBytes.find("LdrLoadDll")->second);
	// free original bytes after use
	delete g_originalBytes.find("LdrLoadDll")->second;

	// call original function
	NTSTATUS ret = fLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);

	// rehook function
	g_originalBytes.find("LdrLoadDll")->second = Util::Memory::HookFunction((DWORD)fLdrLoadDll, (DWORD)HookedLdrLoadDll);

	// return original call value
	return ret;
}

NTSTATUS WINAPI HookedNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD StackZeroBits, DWORD SizeOfStackCommit, DWORD SizeOfstackReserve, CREATE_THREAD_INFO *ThreadInfo) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtCreateThreadEx!\n");
		Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(::GetProcessId(ProcessHandle)) + "\n");
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(::GetThreadId(hThread)) + "\n");
		Util::log<Util::MOREINFO>("Start address: " + Util::decToHexString<DWORD>((DWORD)lpStartAddress) + "\n");
		if (lpParameter)
			Util::log<Util::MOREINFO>("Parameter: " + Util::decToHexString<DWORD>((DWORD)lpParameter) + "\n");
		Util::log<Util::MOREINFO>("Suspended: " + Util::decToHexString<DWORD>((BOOL)CreateSuspended) + "\n");

		if (ProcessHandle != ::GetCurrentProcess()) {
			readHeuristicsFromFile(heuristic);
			heuristic.find(INJECTION_TYPE::PROCESS)->second++;
			heuristic.find(INJECTION_TYPE::SECTION)->second++;
			heuristic.find(INJECTION_TYPE::CODE)->second++;
			heuristic.find(INJECTION_TYPE::DLL)->second++;
			writeHeuristicsToFile(heuristic);

			Util::log<Util::INFO>("Heuristics detected: " + getDetectedHeuristic(heuristic) + "\n");

			Util::log<Util::INFO>("Blocking call...\n\n");
			return 3;	// NT_ERROR
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtCreateThreadEx, g_originalBytes.find("NtCreateThreadEx")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtCreateThreadEx")->second;

	// call original function
	NTSTATUS ret = fNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfstackReserve, ThreadInfo);

	// rehook function
	g_originalBytes.find("NtCreateThreadEx")->second = Util::Memory::HookFunction((DWORD)fNtCreateThreadEx, (DWORD)HookedNtCreateThreadEx);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {

		
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtCreateThread, g_originalBytes.find("NtCreateThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtCreateThread")->second;

	// call original function
	NTSTATUS ret = fNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);

	// rehook function
	g_originalBytes.find("NtCreateThread")->second = Util::Memory::HookFunction((DWORD)fNtCreateThread, (DWORD)HookedNtCreateThread);

	// return original call value
	return ret;
}

// only checking for DLL and atom bombing code injection
NTSTATUS NTAPI HookedNtQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		static unsigned int fileCount = 0;
		//__asm int 3;
		Util::log<Util::SUCCESS>("Hooked NtQueueApcThread!\n");
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(::GetThreadId(ThreadHandle)) + "\n");
		Util::log<Util::MOREINFO>("Thread start: " + Util::decToHexString<DWORD>((DWORD)ApcRoutineContext) + "\n");
		Util::log<Util::MOREINFO>("Parameter at address: " + Util::decToHexString<DWORD>((DWORD)ApcStatusBlock) + "\n\n");

		readHeuristicsFromFile(heuristic);
		if (ApcRoutine == ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "GlobalGetAtomNameW")) {
			Util::log<Util::SUCCESS>("Caught GlobalGetAtomName!\n");
			Util::log<Util::INFO>("Attempting to dump shellcode...\n");

			unsigned int size = (unsigned int)ApcReserved;
			WCHAR *atomBuf = new WCHAR[size + 1];
			::ZeroMemory(atomBuf, size + 1);
			UINT uLen = ::GlobalGetAtomNameW((ATOM)ApcRoutineContext, atomBuf, size);
			dumpRaw("NtQueueApcThread" + std::to_string(fileCount) + "_dump.bin", std::vector<BYTE>((LPBYTE)atomBuf, (LPBYTE)atomBuf + uLen));
			delete[] atomBuf;
			fileCount++;
		} else if (ApcRoutine == ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "GlobalGetAtomNameA")) {
			Util::log<Util::SUCCESS>("Caught GlobalGetAtomName!\n");
			Util::log<Util::INFO>("Attempting to dump shellcode...\n");

			unsigned int size = (unsigned int)ApcReserved;
			CHAR *atomBuf = new CHAR[size + 1];
			::ZeroMemory(atomBuf, size + 1);
			UINT uLen = ::GlobalGetAtomNameA((ATOM)ApcRoutineContext, atomBuf, size);
			dumpRaw("NtQueueApcThread" + std::to_string(fileCount) + "_dump.bin", std::vector<BYTE>((LPBYTE)atomBuf, (LPBYTE)atomBuf + uLen));
			delete[] atomBuf;
			fileCount++;
		} else if (ApcRoutine == ::GetProcAddress(::GetModuleHandle(L"ntdll.dll"), "NtSetContextThread")) {
			Util::log<Util::SUCCESS>("Caught NtSetContextThread!\n");

			Util::log<Util::INFO>("Blocking call...\n\n");
			return 3;	// NT_ERROR
		} else if (ApcReserved != 0) {
			Util::log<Util::INFO>("Suspicious call to NtQueueApcThread!\n");
			Util::log<Util::MOREINFO>("Function address: " + Util::decToHexString<DWORD>((DWORD)ApcRoutine) + "\n\n");
			heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
			writeHeuristicsToFile(heuristic);
		} else {
			// check if legit calls from atom bomb 
			if (!heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second) {
				heuristic.find(INJECTION_TYPE::CODE)->second++;
				heuristic.find(INJECTION_TYPE::DLL)->second++;
				writeHeuristicsToFile(heuristic);
				Util::log<Util::INFO>("Heuristics detected: " + getInjectionTypeString(getHeighestHeuristicKey(heuristic)) + "\n");

				Util::log<Util::INFO>("Blocking call...\n\n");
				return 3;	// NT_ERROR
			}
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtQueueApcThread, g_originalBytes.find("NtQueueApcThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtQueueApcThread")->second;

	// call original function
	NTSTATUS ret = fNtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);

	// rehook function
	g_originalBytes.find("NtQueueApcThread")->second = Util::Memory::HookFunction((DWORD)fNtQueueApcThread, (DWORD)HookedNtQueueApcThread);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtOpenProcess!\n");
		Util::log<Util::MOREINFO>("Process ID: " + Util::decToHexString<DWORD>(::GetProcessId(*ProcessHandle)) + "\n");
		Util::log<Util::MOREINFO>("Desired access: " + Util::decToHexString<DWORD>(DesiredAccess) + "\n\n");

		if (ProcessHandle != ::GetCurrentProcess()) {
			// save target process handle
			g_hProcess = ProcessHandle;

			readHeuristicsFromFile(heuristic);
			heuristic.find(INJECTION_TYPE::CODE)->second++;
			heuristic.find(INJECTION_TYPE::DLL)->second++;
			heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
			writeHeuristicsToFile(heuristic);
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtOpenProcess, g_originalBytes.find("NtOpenProcess")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtOpenProcess")->second;

	// call original function
	NTSTATUS ret = fNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	// rehook function
	g_originalBytes.find("NtOpenProcess")->second = Util::Memory::HookFunction((DWORD)fNtOpenProcess, (DWORD)HookedNtOpenProcess);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked NtOpenThread!\n");
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(::GetThreadId(*ThreadHandle)) + "\n");
		Util::log<Util::MOREINFO>("Desired access: " + Util::decToHexString<DWORD>(DesiredAccess) + "\n\n");

		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::CODE)->second++;
		heuristic.find(INJECTION_TYPE::DLL)->second++;
		heuristic.find(INJECTION_TYPE::ATOM_BOMB)->second++;
		writeHeuristicsToFile(heuristic);
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtOpenThread, g_originalBytes.find("NtOpenThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtOpenThread")->second;

	// call original function
	NTSTATUS ret = fNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

	// rehook function
	g_originalBytes.find("NtOpenThread")->second = Util::Memory::HookFunction((DWORD)fNtOpenThread, (DWORD)HookedNtOpenThread);

	// return original call value
	return ret;
}

//NTSTATUS NTAPI HookedLdrGetProcedureAddressEx(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID *ProcedureAddress, ULONG Flags) {
//	if (::GetCurrentThreadId() == g_dwMainThreadId) {
//		Util::log<Util::PLUS>("Hooked LdrGetProcedureAddressEx!\n");
//		Util::log<Util::MOREINFO>("Procedure name: " + std::string(ProcedureName->Buffer) + "\n");
//		Util::log<Util::MOREINFO>("Ordinal: " + Util::decToHexString<DWORD>(ProcedureNumber) + "\n\n");
//	}
//
//	// unhook to call function
//	Util::Memory::UnhookFunction((DWORD)fLdrGetProcedureAddressEx, g_originalBytes.find("LdrGetProcedureAddressEx")->second);
//	// free original bytes after use
//	delete g_originalBytes.find("LdrGetProcedureAddressEx")->second;
//
//	// call original function
//	NTSTATUS ret = fLdrGetProcedureAddressEx(DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress, Flags);
//
//	// rehook function
//	g_originalBytes.find("LdrGetProcedureAddressEx")->second = Util::Memory::HookFunction((DWORD)fLdrGetProcedureAddressEx, (DWORD)HookedLdrGetProcedureAddressEx);
//
//	// return original call value
//	return ret;
//}

HHOOK WINAPI HookedSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked SetWindowsHookExA!\n");
		Util::log<Util::MOREINFO>("Hook ID: " + Util::decToHexString<DWORD>(idHook) + "\n");
		Util::log<Util::MOREINFO>("Hook procedure: " + Util::decToHexString<DWORD>((DWORD)lpfn) + "\n");
		Util::log<Util::MOREINFO>("Module handle: " + Util::decToHexString<DWORD>((DWORD)hMod) + "\n");
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(dwThreadId) + "\n\n");

		// maybe better heuristic threshold than ' > 0 '?
		// trigger DLL dump
		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::DLL)->second++;
		Util::log<Util::INFO>("Heuristics detected: " + getInjectionTypeString(getHeighestHeuristicKey(heuristic)) + "\n");
		if (heuristic.find(INJECTION_TYPE::DLL)->second > 0 && hMod) {
			Util::log<Util::INFO>("Windows hook DLL injection detected!\n");
			Util::log<Util::INFO>("Heuristics detected: " + getInjectionTypeString(getHeighestHeuristicKey(heuristic)) + "\n");
			Util::log<Util::SUCCESS>("DLL Injection threshold passed! Attempting to dump DLL...\n");

			// read module PE headers
			PIMAGE_NT_HEADERS pinh;
			getPeHeaders(hMod, pinh);
			// read DLL
			DWORD dwSizeOfImage = pinh->OptionalHeader.SizeOfImage;
			std::vector<BYTE> dll(dwSizeOfImage);
			std::copy((LPBYTE)hMod, (LPBYTE)hMod + dwSizeOfImage, dll.begin());

			// dump PE file
			std::vector<BYTE> pe;
			virtualToRaw(pe, dll);
			dumpPe("SetWindowsHookExA_dump.bin", pe.data(), pe.size());

			// clean up
			Util::log<Util::INFO>("Blocking hook...\n");
			Util::log<Util::INFO>("Attempting to unload DLL...\n");
			if (::FreeLibrary(hMod))
				Util::log<Util::SUCCESS>("Successfully unloadeded DLL!\n");
			else
				Util::log<Util::WARNING>("Failed to unload DLL\n\n");

			//Util::log<Util::INFO>("Terminating process...\n");
			//::ExitProcess(0);
			//heuristic.find(INJECTION_TYPE::DLL)->second = 0;
			//writeHeuristicsToFile(heuristic);

			return nullptr;
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)::GetProcAddress(::GetModuleHandle(L"user32.dll"), "SetWindowsHookExA"), g_originalBytes.find("SetWindowsHookExA")->second);
	// free original bytes after use
	delete g_originalBytes.find("SetWindowsHookExA")->second;

	// call original function
	HHOOK ret = ::SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);

	// rehook function
	g_originalBytes.find("SetWindowsHookExA")->second = Util::Memory::HookFunction((DWORD)::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "SetWindowsHookExA"), (DWORD)HookedSetWindowsHookExA);

	// return original call value
	return ret;
}

HHOOK WINAPI HookedSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
	if (::GetCurrentThreadId() == g_dwMainThreadId) {
		Util::log<Util::SUCCESS>("Hooked SetWindowsHookExW!\n");
		Util::log<Util::MOREINFO>("Hook ID: " + Util::decToHexString<DWORD>(idHook) + "\n");
		Util::log<Util::MOREINFO>("Hook procedure: " + Util::decToHexString<DWORD>((DWORD)lpfn) + "\n");
		Util::log<Util::MOREINFO>("Module handle: " + Util::decToHexString<DWORD>((DWORD)hMod) + "\n");
		Util::log<Util::MOREINFO>("Thread ID: " + Util::decToHexString<DWORD>(dwThreadId) + "\n\n");

		// maybe better heuristic threshold than ' > 0 '?
		// trigger DLL dump
		readHeuristicsFromFile(heuristic);
		heuristic.find(INJECTION_TYPE::DLL)->second++;
		Util::log<Util::INFO>("Heuristics detected: " + getInjectionTypeString(getHeighestHeuristicKey(heuristic)) + "\n");
		if (heuristic.find(INJECTION_TYPE::DLL)->second > 0 && hMod) {
			Util::log<Util::INFO>("Windows hook DLL injection detected!\n");
			Util::log<Util::SUCCESS>("DLL Injection threshold passed! Attempting to dump DLL...\n");

			// read module PE headers
			PIMAGE_NT_HEADERS pinh;
			getPeHeaders(hMod, pinh);
			// read DLL
			DWORD dwSizeOfImage = pinh->OptionalHeader.SizeOfImage;
			std::vector<BYTE> dll(dwSizeOfImage);
			std::copy((LPBYTE)hMod, (LPBYTE)hMod + dwSizeOfImage, dll.begin());

			// dump PE file
			std::vector<BYTE> pe;
			virtualToRaw(pe, dll);
			dumpPe("SetWindowsHookExW_dump.bin", pe.data(), pe.size());

			// clean up
			Util::log<Util::INFO>("Blocking hook...\n");
			Util::log<Util::INFO>("Attempting to unload DLL...\n");
			if (::FreeLibrary(hMod))
				Util::log<Util::SUCCESS>("Successfully unloaded DLL!\n");
			else
				Util::log<Util::WARNING>("Failed to unload DLL\n\n");

			//Util::log<Util::INFO>("Terminating process...\n");
			//::ExitProcess(0);
			//heuristic.find(INJECTION_TYPE::DLL)->second = 0;
			//writeHeuristicsToFile(heuristic);

			return nullptr;
		}
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)::GetProcAddress(::GetModuleHandle(L"user32.dll"), "SetWindowsHookExW"), g_originalBytes.find("SetWindowsHookExW")->second);
	// free original bytes after use
	delete g_originalBytes.find("SetWindowsHookExW")->second;

	// call original function
	HHOOK ret = ::SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);

	// rehook function
	g_originalBytes.find("SetWindowsHookExW")->second = Util::Memory::HookFunction((DWORD)::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "SetWindowsHookExW"), (DWORD)HookedSetWindowsHookExW);

	// return original call value
	return ret;
}