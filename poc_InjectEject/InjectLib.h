#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <strsafe.h>

#ifdef UNICODE
#define InjectLib InjectLibW
#else
#define InjectLib InjectLibA
#endif

class POC_InjectLib {
public:
	POC_InjectLib();
	static BOOL InjectLibW(DWORD dwPID, PCWSTR szDllPath);
	static BOOL InjectLibA(DWORD dwPID, PCSTR szDllPath);
};