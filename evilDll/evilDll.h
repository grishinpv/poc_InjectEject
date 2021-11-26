#pragma once

#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <tchar.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <strsafe.h>


#ifdef SNEVTAPI_EXPORTS
#define SNEVTAPI_API extern "C" __declspec(dllexport)
#else
#define SNEVTAPI_API extern "C" __declspec(dllimport)
#endif


#ifdef EVILDLL_EXPORTS
#define EVILDLL_API extern "C" __declspec(dllexport)
#else
#define EVILDLL_API extern "C" __declspec(dllimport)
#endif


EVILDLL_API int poc(int code, WPARAM wParam, LPARAM lParam);
SNEVTAPI_API int SnSelfdefElevatePrivilege(void);