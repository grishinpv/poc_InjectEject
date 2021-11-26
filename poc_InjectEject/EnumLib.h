#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <strsafe.h>

#ifdef UNICODE
#define EnumLib EnumLibW
#else
#define EnumLib EnumLibA
#endif

class POC_EnumLib {
public:
	POC_EnumLib();
	static BOOL EnumLibW(DWORD dwPID, PCWSTR szDllName, MODULEENTRY32 &fModule);
	static BOOL EnumLibA(DWORD dwPID, PCSTR szDllName, MODULEENTRY32 &fModule);
};