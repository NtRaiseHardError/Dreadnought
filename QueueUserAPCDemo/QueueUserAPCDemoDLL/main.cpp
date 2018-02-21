#include <Windows.h>

extern "C" void __declspec(dllexport) Demo() {
	::MessageBox(nullptr, L"This is a demo!", L"Demo", MB_OK);
}

bool APIENTRY DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH)
		::CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Demo, nullptr, 0, nullptr);
	return true;
}