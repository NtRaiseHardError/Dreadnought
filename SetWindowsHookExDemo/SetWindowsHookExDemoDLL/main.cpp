#include <Windows.h>

extern "C" void __declspec(dllexport) Demo() {
	::MessageBox(nullptr, L"This is a demo!", L"Demo", MB_OK);
}

int APIENTRY DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {

	return true;
}