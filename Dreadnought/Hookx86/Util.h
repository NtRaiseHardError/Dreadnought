#pragma once
#ifndef __UTIL_H__
#define __UTIL_H__

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <exception>
#include <Windows.h>
#include <Shlwapi.h>

#define LIGHT_GREEN FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define DARK_GREEN FOREGROUND_GREEN
#define LIGHT_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define DARK_YELLOW FOREGROUND_GREEN | FOREGROUND_RED
#define LIGHT_YELLOW FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define LIGHT_BLUE FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define TURQUOISE FOREGROUND_BLUE | FOREGROUND_GREEN
#define CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define WHITE FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define GRAY FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED

namespace Util {
	enum DebugType {
		INFO,
		WARNING,
		SUCCESS,
		FAILURE,
		MOREINFO
	};

	/*
	 * Displays synchronous message box.
	 * PARAM fmt : format string
	 * PARAM args : variadic arguments corresponding to format string fmt
	 */
	template<typename... Args>
	static void MsgBox(LPTSTR fmt, Args&&... args) {
		TCHAR szBuf[1024];

		wsprintf(szBuf, fmt, std::forward<Args>(args)...);
		::MessageBox(NULL, szBuf, TEXT(""), MB_OK);
	}

	template<DebugType D>
	static void debug(const std::string& s) {
		std::string str;
		WORD colour = 0;
		switch (D) {
			case INFO:
				str = "*";
				colour = WHITE;
				break;
			case WARNING:
				str = "!";
				colour = LIGHT_YELLOW;
				break;
			case SUCCESS:
				str = "+";
				colour = LIGHT_GREEN;
				break;
			case FAILURE:
				str = "-";
				colour = LIGHT_RED;
				break;
			case MOREINFO:
				str = ">>>";
				colour = TURQUOISE;
				break;
		}

		if (D != MOREINFO)
			std::cout << "[";

		// change console colours
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		::GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
		::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);

		std::cout << str;

		// revert console colours
		::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);

		if (D != MOREINFO)
			std::cout << "]";

		std::cout << " " << s;
	}

	template<DebugType D>
	static void log(const std::string& s) {
#ifdef _DEBUG
		Util::debug<D>(s);
#endif // DEBUG

		CHAR szPath[MAX_PATH + 1];
		::ZeroMemory(szPath, MAX_PATH + 1);
		::GetModuleFileNameA(nullptr, szPath, MAX_PATH);

		CHAR szTemp[MAX_PATH + 1];
		::StrCpyA(szTemp, ::PathFindFileNameA(szPath));
		::PathRemoveExtensionA(szTemp);

		std::string logPath = "Dumps\\";
		logPath += szTemp;

		::CreateDirectoryA(logPath.c_str(), nullptr);

		logPath += "\\";
		logPath += "log.txt";

		std::ofstream logfile;
		logfile.open(logPath, std::wofstream::out | std::wofstream::app);

		std::string str;
		switch (D) {
			case INFO:
				str = "*";
				break;
			case WARNING:
				str = "!";
				break;
			case SUCCESS:
				str = "+";
				break;
			case FAILURE:
				str = "-";
				break;
			case MOREINFO:
				str = ">>>";
				break;
		}

		if (D != MOREINFO)
			logfile << "[";

		logfile << str;

		if (D != MOREINFO)
			logfile << "]";

		logfile << " " << s;

		logfile.close();
	}

	static void fatal(const std::string& s) {
		Util::log<Util::FAILURE>(s);
		::ExitProcess(1);
	}

	template< typename T >
	std::string decToHexString(T decimal) {
		std::stringstream stream;
		stream << "0x"
			<< std::setfill('0') << std::setw(sizeof(T) * 2)
			<< std::hex << decimal;
		return stream.str();
	}

	/*
	 * Utility for basic memory manipulation.
	 */
	class Memory {
		private:
			Memory() {}
			~Memory() {}
		public:
			/*
			 * Reads T-sized memory defined by generic parameter T.
			 * PARAM lpAddress : Address from which to be read
			 * RETURN : T-defined value read from lpAddress
			 */
			template<typename T>
			static T ReadMemory(LPVOID lpAddress) {
				return *((T *)lpAddress);
			}

			/*
			 * Writes T-sized memory defined by generic parameter T.
			 * PARAM lpAddress : Address to which to be written
			 */
			template<typename T>
			static void WriteMemory(LPVOID lpAddress, T value) {
				*((T *)lpAddress) = value;
			}

			template<typename T>
			T* PointMemory(DWORD address) {
				return ((T*)address);
			}

			/*
			 * Protects T-sized memory defined by generic parameter T.
			 * PARAM lpAddress : Address from which to be protected
			 * PARAM size : Size of memory to be protected
			 * PARAM flProtect : Protection type
			 * RETURN : Previous protection type
			 */
			template<typename T>
			static DWORD ProtectMemory(LPVOID lpAddress, SIZE_T size, DWORD flProtect) {
				DWORD flOldProtect = 0;
				::VirtualProtect(lpAddress, size, flProtect, &flOldProtect);

				return flOldProtect;
			}

			/*
			 * Hooks a function in the virtual table of a specified class.
			 * PARAM classInst : Instance of the class which contains the virtual table
			 * PARAM funcIndex : Index of the virtual function in the virtual table
			 * PARAM newFunc : Address of the new function
			 * RETURN : Address of the original function
			 */
			static DWORD HookVirtualFunction(DWORD classInst, DWORD funcIndex, DWORD newFunc) {
				DWORD VFTable = ReadMemory<DWORD>((LPVOID)classInst);
				DWORD hookAddress = VFTable + funcIndex * sizeof(DWORD);

				DWORD flOldProtect = ProtectMemory<DWORD>((LPVOID)hookAddress, sizeof(DWORD), PAGE_READWRITE);

				DWORD originalFunc = ReadMemory<DWORD>((LPVOID)hookAddress);
				WriteMemory<DWORD>((LPVOID)hookAddress, newFunc);

				ProtectMemory<DWORD>((LPVOID)hookAddress, sizeof(DWORD), flOldProtect);

				return originalFunc;
			}
			 /*
			  * Retrieves the address of a virtual function.
			  * PARAM classInst : Instance of the class which contains the virtual function
			  * PARAM funcIndex : Index of the cirtual function in the virtual table
			  * RETURN : Address of the function
			  */
			static DWORD GetVirtualFunction(DWORD classInst, DWORD funcIndex) {
				DWORD dwVFTable = ReadMemory<DWORD>((LPVOID)classInst);
				DWORD dwHookAddress = dwVFTable + funcIndex * sizeof(DWORD);
				return ReadMemory<DWORD>((LPVOID)dwHookAddress);
			}

			/*
			 * Hooks a function using push/ret method.
			 * PARAM dwFuncAddress : Address of the function to hook
			 * PARAM dwNewAddress : Address of the new function
			 * RETURN : Pointer to the original 6 bytes replaced by the push/ret
			 */
			static LPBYTE HookFunction(DWORD dwFuncAddress, DWORD dwNewAddress) {
				// save original bytes
				LPBYTE origBytes = new BYTE[6];
				for (int i = 0; i < 6; i++)
					origBytes[i] = ReadMemory<BYTE>((LPVOID)(dwFuncAddress + i));

				// enable write permissions
				DWORD flOldProtect = ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, PAGE_EXECUTE_READWRITE);

				// jump hook (using push/ret)
				WriteMemory<BYTE>((LPVOID)dwFuncAddress, 0x68);	// push
				WriteMemory<DWORD>((LPVOID)(dwFuncAddress + 1), dwNewAddress);
				WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 5), 0xC3);	// ret

				// restore permissions
				ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, flOldProtect);

				return origBytes;
			}

			/*
			 * Unhooks a function using the push/ret method.
			 * PARAM dwFuncAddress : Address of the function to unhook
			 * PARAM origBytes : Pointer to the original 6 bytes replaced by the pust/ret
			 */
			static void UnhookFunction(DWORD dwFuncAddress, LPBYTE origBytes) {
				// enable write permissions
				DWORD flOldProtect = ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, PAGE_EXECUTE_READWRITE);

				// restore bytes
				for (int i = 0; i < 6; i++)
					WriteMemory<BYTE>((LPVOID)(dwFuncAddress + i), origBytes[i]);

				// restore permissions
				ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, flOldProtect);
			}
	};


}

#endif // !__UTIL_H__
