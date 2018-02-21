#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
//#include <TlHelp32.h>

#define DLL_NAME "QueueUserAPCDemoDLL.dll"

int main(int argc, char *argv[]) {

	CHAR szProcess[MAX_PATH + 1];
	::ZeroMemory(szProcess, MAX_PATH + 1);
	//::GetModuleFileNameA(nullptr, szProcess, MAX_PATH);
	::GetSystemDirectoryA(szProcess, MAX_PATH);

	std::string proc = szProcess;
	proc += "\\";
	proc += "notepad.exe";

	CHAR szCurrPath[MAX_PATH + 1];
	::ZeroMemory(szCurrPath, MAX_PATH + 1);
	::GetCurrentDirectoryA(MAX_PATH, szCurrPath);

	std::string dllPath = szCurrPath;
	dllPath += "\\";
	dllPath += DLL_NAME;

	// prevent recursion
	if (::GetModuleHandleA(dllPath.c_str()))
		return 0;

	STARTUPINFOA si;
	::ZeroMemory(&si, sizeof(STARTUPINFOA));
	si.cb = sizeof(STARTUPINFOA);

	PROCESS_INFORMATION pi;
	::ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	// create process suspended which will later be resumed to trigger alert state that will activate the APC
	if (!::CreateProcessA(proc.c_str(), nullptr, nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi)) {
		std::cout << "Error creating process: " << ::GetLastError() << "\n";
		return 1;
	}

	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, false, pi.dwProcessId);
	if (!hProcess) {
		std::cout << "Error opening process: " << ::GetLastError() << "\n";
		return 1;
	}

	HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, false, pi.dwThreadId);
	if (!hThread) {
		std::cout << "Error opening thread: " << ::GetLastError() << "\n";
		return 1;
	}

	// allocate memory for DLL path string
	LPVOID lpLoadLibraryParam = ::VirtualAllocEx(hProcess, nullptr, dllPath.length(), MEM_COMMIT, PAGE_READWRITE);
	if (!lpLoadLibraryParam) {
		std::cout << "Error allocating DLL memory: " << ::GetLastError() << "\n";
		return 1;
	}

	// write DLL string to memory
	DWORD dwWritten = 0;
	if (!::WriteProcessMemory(hProcess, lpLoadLibraryParam, dllPath.data(), dllPath.length(), &dwWritten)) {
		std::cout << "Error writing memory: " << ::GetLastError() << "\n";
		return 1;
	}

	// queue APC call to LoadLibraryA(dllPath)
	if (!::QueueUserAPC((PAPCFUNC)::GetProcAddress(::GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), hThread, (ULONG_PTR)lpLoadLibraryParam)) {
		std::cout << "Error in APC: " << ::GetLastError() << "\n";
		return 1;
	}

	//HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	//if (hSnapshot == INVALID_HANDLE_VALUE) {
	//	std::cout << "Error snapshotting threads: " << ::GetLastError() << "\n";
	//	return 1;
	//}

	//THREADENTRY32 te32;
	//te32.dwSize = sizeof(THREADENTRY32);
	//if (::Thread32First(hSnapshot, &te32)) {
	//	do {
	//		if (te32.th32OwnerProcessID == ::GetProcessId(hProcess)) {
	//			// resume thread to trigger alert state to activate above APC
	//			//::ResumeThread(hThread);
	//		}
	//	} while (::Thread32Next(hSnapshot, &te32));
	//}

	return 0;
}