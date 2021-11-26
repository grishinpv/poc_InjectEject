#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <strsafe.h>

#ifdef UNICODE
#define EjectLib EjectLibW
#else
#define EjectLib EjectLibA
#endif

class POC_EjectLib {
public:
	POC_EjectLib();
	static BOOL EjectLibW(DWORD dwPID, PCWSTR szDllPath);
	static BOOL EjectLibA(DWORD dwPID, PCSTR szDllPath);
};
