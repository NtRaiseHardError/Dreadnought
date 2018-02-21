#include <thread>
#include <Windows.h>

#include "hookhelper.h"

int APIENTRY DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			::CreateDirectoryA("Dumps", nullptr);
			::CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)initialiseHooks, nullptr, 0, nullptr);
			break;
		case DLL_PROCESS_DETACH:
			//::DeleteFile(L"heuristics");
			break;
	}

	return true;
}