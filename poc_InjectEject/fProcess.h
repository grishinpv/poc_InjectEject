#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <stdio.h>

#ifdef UNICODE
#define FindProcessID FindProcessID_W
#else
#define FindProcessID FindProcessID_A
#endif

class POC_fProcess {
public:
	POC_fProcess();
	static DWORD FindProcessID_W(PCWSTR szProcessName);
	static DWORD FindProcessID_A(PCSTR szProcessName);
	static DWORD getThreadID(DWORD pid);
	static BOOL StopService(PCWSTR szProcessName, int delay = 0);
	static BOOL killProcessByName(PCWSTR szProcessName, int delay = 0);
	static BOOL SetServiceType_DISABLE(PCWSTR szProcessName, int delay = 0);
	static BOOL RenameFile(PCWSTR szOldPath, PCWSTR szNewPath, int delay = 0);
	static BOOL StartHollowed(LPWSTR szTarget, LPWSTR szEvilSubstitute, int delay = 0);
	static BOOL NTkillProcessByName(PCWSTR szProcessName, int delay = 0);
	static BOOL RemoveAllPrivileges(PCWSTR szProcessName, int delay = 0);
	static BOOL Echo(PCWSTR szDestPath, PCWSTR szText = L"evil_Text", int delay = 0, bool threaded = FALSE);

};