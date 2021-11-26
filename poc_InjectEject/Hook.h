#pragma once


#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <strsafe.h>

class POC_Hook {
public:
	POC_Hook();
	static BOOL demoSetWindowsHookEx(DWORD dwProcessId, PCWSTR strProcName, PCWSTR pszLibFile);
};