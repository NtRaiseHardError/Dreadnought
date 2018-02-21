#pragma once
#ifndef __UTIL_H__
#define __UTIL_H__

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <exception>
#include <Windows.h>

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

	/*
	 * Severity of a log used by Logger class.
	 * INFO : general information
	 * WARNING : non-fatal error; can be dismissed
	 * SEVERE : fatal error
	 */
	enum class LogLevel {
		INFO,
		WARNING,
		SEVERE		// error
	};

	/*
	 * Utility to log information to a file.
	 */
	class Logger {
		private:
			unsigned int numWarnings;
			unsigned int numErrors;
			std::wofstream log;

			/*
			 * Constructor initialises members and log file.
			 */
			Logger() {
				TCHAR szCurrentDir[MAX_PATH];
				::GetCurrentDirectory(MAX_PATH, szCurrentDir);

				std::wstring outputFileName(szCurrentDir);
				outputFileName += TEXT("\\CSGO_haqs_log.txt");
				log = std::wofstream(outputFileName.c_str(), std::ios::out | std::ios::app);
			}
			~Logger() {}
			
			// Deny copy/assignment of this class
			Logger(Logger& l) {}
			Logger& operator=(Logger& l) {}

			static void Log(std::wofstream& stream, LPTSTR fmt) {
				(stream << fmt);
			}
		public:
			/*
			 * Logs a string to the log file.
			 * PARAM L : Severity of log defined by an enum LogLevel member
			 * PARAM fmt : format string
			 * PARAM args : variadic arguments corresponding to format string fmt
			 */
			template<LogLevel L, typename... Args>
			static void Log(LPTSTR fmt, Args&&... args) {
				TCHAR szBuf[1024];
				wsnprintf(szBuf, 1024, fmt, std::forward<Args>(args));
				switch (L) {
					case LogLevel::INFO:
						Log(log, TEXT("[INFO] : ") << szBuf);
						break;
					case LogLevel::WARNING:
						Log(log, TEXT("[WARNING] : ") << szBuf);
						break;
					case LogLevel::SEVERE:
						Log(log, TEXT("[SEVERE] : ") << szBuf);
						break;
					default:
						throw new std::invalid_argument("Invalid LogLevel specified.");
				}
			}

			/*
			 * Logs to a user-defined ofstream.
			 * PARAM L : Severity of log defined by an enum LogLevel member
			 * PARAM stream : User-defined wofstream output
			 * PARAM fmt : format string
			 * PARAM args : variadic arguments corresponding to format string fmt
			 */
			template<LogLevel L, typename... Args>
			static void Log(std::wofstream& stream, LPTSTR fmt, Args&&... args) {
				TCHAR szBuf[1024];
				wsnprintf(szBuf, 1024, fmt, std::forward<Args>(args));
				switch (L) {
					case LogLevel::INFO:
						Log(stream, TEXT("[INFO] : ") << szBuf);
						break;
					case LogLevel::WARNING:
						Log(stream, TEXT("[WARNING] : ") << szBuf);
						break;
					case LogLevel::SEVERE:
						Log(stream, TEXT("[SEVERE] : ") << szBuf);
						break;
					default:
						throw new std::invalid_argument("Invalid LogLevel specified.");
				}
			}
	};

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
