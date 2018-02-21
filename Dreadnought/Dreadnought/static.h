#pragma once
#ifndef __STATIC_H__
#define __STATIC_H__

#include <Windows.h>

bool analyseImports(const std::vector<BYTE>& file);
bool analyseStrings(const std::vector<BYTE>& file);

#endif // !__STATIC_H__
