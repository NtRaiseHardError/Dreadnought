#include <iostream>
#include <string>
#include <Windows.h>
#include <Shlwapi.h>

#include "dynamic.h"
#include "Util.h"

#pragma comment(lib, "Shlwapi.lib")

bool createChildProcess(const std::string fileName, const std::string args, HANDLE& hProcess, HANDLE& hThread) {
	STARTUPINFOA si;
	::ZeroMemory(&si, sizeof(STARTUPINFOA));
	si.cb = sizeof(STARTUPINFOA);

	PROCESS_INFORMATION pi;
	::ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	//std::string arguments = " " + args;
	if (!::CreateProcessA(fileName.c_str(), (LPSTR)(" " + args).c_str(), nullptr, nullptr, true, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
		return false;

	hThread = pi.hThread;
	hProcess = pi.hProcess;

	return true;
}

bool injectDll(const HANDLE hProcess, const std::string dllPath) {
	LPVOID lpBaseAddress = ::VirtualAllocEx(hProcess, nullptr, dllPath.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress) {
		DWORD dwWritten = 0;
		if (::WriteProcessMemory(hProcess, lpBaseAddress, dllPath.c_str(), dllPath.length(), &dwWritten)) {
			HMODULE hModule = ::GetModuleHandle(L"kernel32.dll");
			if (hModule) {
				LPVOID lpStartAddress = ::GetProcAddress(hModule, "LoadLibraryA");
				if (lpStartAddress) {
					if (::CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, nullptr)) {
						return true;
					}
				}
			}
		}
	}

	::VirtualFreeEx(hProcess, lpBaseAddress, dllPath.length(), MEM_DECOMMIT);
	return false;
}

bool dynamicAnalysis(const std::string fileName, const std::string args) {
	// locate hooking dll
	char currentDir[MAX_PATH + 1];
	::GetCurrentDirectoryA(MAX_PATH, currentDir);

	std::string dllPath = currentDir;
	dllPath += "\\";
	dllPath += DLL_NAME;

	if (::PathFileExistsA(dllPath.c_str()))
		Util::debug<Util::INFO>("Found " + dllPath + "\n");
	else {
		Util::debug<Util::FAILURE>("Error locating " + dllPath + "\n");
		return false;
	}

	Util::debug<Util::INFO>("Creating " + fileName + " as a suspended process...\n");
	Util::debug<Util::INFO>("Command line: " + fileName + " " + args + "\n");

	// start target file as child process
	HANDLE hProcess = nullptr, hThread = nullptr;
	if (!createChildProcess(fileName, args, hProcess, hThread))
		return false;
	Util::debug<Util::SUCCESS>("Success!\n\n");

	// inject hook
	Util::debug<Util::INFO>("Injecting hook...\n");
	if (!injectDll(hProcess, dllPath)) {
		::TerminateProcess(hProcess, 0);
		return false;
	}

	Util::debug<Util::INFO>("Awaiting completion...\n");
	::WaitForSingleObject(hProcess, INFINITE);

	DWORD dwExitCode = 0;
	if (::GetExitCodeProcess(hProcess, &dwExitCode)) {
		if (dwExitCode == 0)
			Util::debug<Util::SUCCESS>("Process exited successfully!\n");
		else
			Util::debug<Util::WARNING>("Process exited with error code: " + std::to_string(dwExitCode) + "\n");
	}

	::CloseHandle(hThread);
	::CloseHandle(hProcess);

	return true;
}