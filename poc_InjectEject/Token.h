#pragma once

#include <windows.h>
#include <vector>


class POC_Token {
	public:
		POC_Token();
		static HANDLE GetProcessToken(DWORD dwPID = 0);
		//static std::vector<LPWSTR> TokenPrivilegesToString(PTOKEN_PRIVILEGES *pTokenPriv);
		static BOOL GetPrivilegesFromProcess(PTOKEN_PRIVILEGES *pTokenPriv, DWORD dwPID = 0 );
		static BOOL RemovePrivilegesFromProcess(PTOKEN_PRIVILEGES pTokenPriv, DWORD dwPID = 0);
};