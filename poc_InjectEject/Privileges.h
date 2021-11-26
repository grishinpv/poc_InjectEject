#pragma once
#include <Windows.h>
#include <tchar.h>

class POC_Privileges {
public:
	POC_Privileges();
	static BOOL ElevatePrivilege(DWORD dwPID, PCWSTR szProcPath);
	static BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	static BOOL ElevatePrivilege_SetThreadToken (DWORD dwPID, PCWSTR szProcPath);
};