#include <string>
#include <Windows.h>

#define DLL_NAME L"SetWindowsHookExDemoDLL.dll"

int main() {
	//WCHAR szPath[MAX_PATH + 1];
	//::ZeroMemory(szPath, MAX_PATH + 1);
	//::GetCurrentDirectory(MAX_PATH, szPath);
	//std::wstring dllPath = szPath;
	//dllPath += L"\\";
	std::wstring dllPath = DLL_NAME;

	HMODULE hMod = ::LoadLibrary(dllPath.c_str());
	HOOKPROC lpfn = (HOOKPROC)::GetProcAddress(hMod, "Demo");
	HHOOK hHook = ::SetWindowsHookEx(WH_GETMESSAGE, lpfn, hMod, ::GetCurrentThreadId());
	if (!::PostThreadMessageW(::GetCurrentThreadId(), WM_RBUTTONDOWN, (WPARAM)0, (LPARAM)0))
		return 1;

	MSG msg;
	while (::GetMessage(&msg, nullptr, 0, 0) > 0) {
		::TranslateMessage(&msg);
		::DispatchMessage(&msg);
	}

	::UnhookWindowsHookEx(hHook);
}