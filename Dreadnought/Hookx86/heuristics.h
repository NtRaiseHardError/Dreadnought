#pragma once
#ifndef __HEURISTICS_H__
#define __HEURISTICS_H__

#include <string>
#include <map>

typedef enum _INJECTION_TYPE {
	SECTION,
	PROCESS,
	DLL,
	CODE,
	ATOM_BOMB,
	DOPPELGANGING
} INJECTION_TYPE;

extern std::map<INJECTION_TYPE, unsigned int> heuristic;

INJECTION_TYPE getHeighestHeuristicKey(std::map<INJECTION_TYPE, unsigned int>& heuristic);
std::string getInjectionTypeString(INJECTION_TYPE type);
std::string getDetectedHeuristic(std::map<INJECTION_TYPE, unsigned int>& heuristic);
void writeHeuristicsToFile(std::map<INJECTION_TYPE, unsigned int>& heuristic);
void readHeuristicsFromFile(std::map<INJECTION_TYPE, unsigned int>& heuristic);

#endif // !__HEURISTICS_H__
