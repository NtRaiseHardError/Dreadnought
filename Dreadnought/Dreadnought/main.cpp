#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

#include "dynamic.h"
#include "getopt.h"
#include "static.h"
#include "Util.h"

static bool read(const std::string fileName, std::vector<BYTE>& data) {
	// open handle to file
	DWORD dwAttributes = ::GetFileAttributesA(fileName.c_str());
	HANDLE hFile = ::CreateFileA(fileName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, dwAttributes, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwRead = 0;
	DWORD dwSize = ::GetFileSize(hFile, nullptr);
	std::vector<BYTE> file(dwSize);
	if (!::ReadFile(hFile, &file[0], dwSize, &dwRead, nullptr)) {
		::CloseHandle(hFile);
		return false;
	}

	data = file;

	return true;
}

static void printTitle() {
	// change console colours
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	::GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	// randomise colour
	std::vector<WORD> allColours({ FOREGROUND_BLUE, FOREGROUND_GREEN, FOREGROUND_RED,
								 FOREGROUND_BLUE | FOREGROUND_RED, FOREGROUND_BLUE | FOREGROUND_GREEN, FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
								 FOREGROUND_RED | FOREGROUND_GREEN, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
								 FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY });

	std::srand((unsigned int)__rdtsc());
	WORD colour = allColours.at(std::rand() % allColours.size());

	::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);

	std::cout << "\n"
		"    ____                      __                        __    __ \n"
		"   / __ \\________  ____ _____/ /___  ____  __  ______ _/ /_  / /_\n"
		"  / / / / ___/ _ \\/ __ `/ __  / __ \\/ __ \\/ / / / __ `/ __ \\/ __/\n"
		" / /_/ / /  /  __/ /_/ / /_/ / / / / /_/ / /_/ / /_/ / / / / /_  \n"
		"/_____/_/   \\___/\\__,_/\\__,_/_/ /_/\\____/\\__,_/\\__, /_/ /_/\\__/  \n"
		"                                              /____/             \n\n"
		"					-- developed by dtm\n\n";

	// revert console colours
	::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);
}

static void printSyntax(std::string self) {
	std::cout << "Syntax: " << self << " [-adhs] FILE\n\n"
				"\t-a\tArguments for target process (only available in dynamic mode).\n\n"
				"\t-d\tEnables dynamic analysis (this will execute the file!).\n\n"
				"\t-h\tPrints this screen.\n\n"
				"\t-s\tEnables static analysis (import and string scan).\n\n"
				"FILE should be a native executable PE file.\n\n";
}

int main(int argc, char *argv[]) {
	printTitle();

	if (argc < 3) {
		printSyntax(argv[0]);
		return 1;
	}

	int c;
	bool dynamic = false, statik = false;
	std::string dynamicArgs;
	// parse options
	while ((c = getopt(argc, argv, "a:dhs")) != -1) {
		switch (c) {
			case 'a':
				dynamicArgs = optarg;
				break;
			case 'd':
				dynamic = true;
				break;
			case 's':
				statik = true;
				break;
			case 'h':
			default:
				printSyntax(argv[0]);
				return 1;
		}
	}

	// get target file
	std::string targetfile;
	for (int index = optind; index < argc; index++)
		targetfile = argv[index];

	// check if target file is empty
	if (targetfile.empty()) {
		Util::debug<Util::FAILURE>("Please provide a target file!\n");
		return 1;
	}

	// read file into vector
	std::vector<BYTE> file;
	if (!read(targetfile, file)) {
		Util::debug<Util::FAILURE>("Error reading target file \"" + targetfile + "\": " + std::to_string(::GetLastError()) + "\n");
		return 1;
	}

	// static analysis
	if (statik) {
		// scan imports
		Util::debug<Util::INFO>("Scanning for suspicious imports...\n");
		if (!analyseImports(file))
			Util::debug<Util::FAILURE>("Error analysing imports: " + std::to_string(::GetLastError()) + "\n\n");

		// scan strings
		Util::debug<Util::INFO>("Scanning for suspicious strings...\n");
		if (!analyseStrings(file))
			Util::debug<Util::FAILURE>("Error analysing strings: " + std::to_string(::GetLastError()) + "\n\n");
	}

	// dyamic anlaysis
	if (dynamic) {
		Util::debug<Util::INFO>("Starting dynamic analysis...\n");
		if (!dynamicAnalysis(targetfile, dynamicArgs))
			Util::debug<Util::FAILURE>("Error starting dynamic analysis: " + std::to_string(::GetLastError()) + "\n\n");
	}

	Util::debug<Util::INFO>("Analysis complete.\n");

	return 0;
}