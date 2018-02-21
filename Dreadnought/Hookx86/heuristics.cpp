#include <fstream>

#include "heuristics.h"

INJECTION_TYPE getHeighestHeuristicKey(std::map<INJECTION_TYPE, unsigned int>& heuristic) {
	INJECTION_TYPE maxKey;
	unsigned int curr = 0;
	for (const auto h : heuristic) {
		if (h.second > curr) {
			curr = h.second;
			maxKey = h.first;
		}
	}

	return maxKey;
}

std::string getInjectionTypeString(INJECTION_TYPE type) {
	switch (type) {
		case INJECTION_TYPE::ATOM_BOMB:
			return "Atom Bombing";
		case INJECTION_TYPE::CODE:
			return "Code injection";
		case INJECTION_TYPE::DLL:
			return "DLL Injection";
		case INJECTION_TYPE::DOPPELGANGING:
			return "Process Doppelganging";
		case INJECTION_TYPE::PROCESS:
			return "Process Injection";
		case INJECTION_TYPE::SECTION:
			return "Section Injection";
	}

	return "";
}

std::string getDetectedHeuristic(std::map<INJECTION_TYPE, unsigned int>& heuristic) {
	// get max value
	unsigned int max = 0;
	for (const auto h : heuristic) {
		if (h.second > max) {
			max = h.second;
		}
	}

	std::string detected;
	for (const auto h : heuristic) {
		if (h.second == max) {
			if (detected.empty())
				detected = getInjectionTypeString(h.first);
			else {
				detected += " or ";
				detected += getInjectionTypeString(h.first);
			}
		}
	}

	return detected;
}

void writeHeuristicsToFile(std::map<INJECTION_TYPE, unsigned int>& heuristic) {
	std::ofstream file("heuristics", std::ofstream::out);

	for (const auto h : heuristic) {
		file << h.first << " ";
		file << h.second << "\n";
	}

	file.close();
}

void readHeuristicsFromFile(std::map<INJECTION_TYPE, unsigned int>& heuristic) {
	std::ifstream file("heuristics", std::istream::in);

	unsigned int type;
	unsigned int weight = 0;
	while (file >> type >> weight) {
		heuristic.insert({ (INJECTION_TYPE)type, weight });
	}
}