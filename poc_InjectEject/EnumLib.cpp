#pragma once

#include "EnumLib.h"
#include "Helper.h"

using namespace std;

POC_EnumLib::POC_EnumLib()
{
}

BOOL POC_EnumLib::EnumLibW(DWORD dwPID, PCWSTR szDllName, MODULEENTRY32 &fModule) {

	OutputDebugString(TEXT("[evil_POC] EnumLibW -->"));

	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot = NULL;
	LPCTSTR strErrorMessage = NULL;
	DWORD dwLastError = 0;

	// Get DLL_NAME in dwPID process with TH32CS_SNAPMODULE Parameter
	wprintf(L"Get process snapshot...\n");
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		dwLastError = GetLastError();
		strErrorMessage = POC_Helper::strGetLastError(dwLastError);
		OutputDebugString((TEXT("[evil_POC] EnumLibW --> CreateToolhelp32Snapshot Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
		wprintf(L"w> Fail\n");
		throw 1;
	}

	wprintf(L"Enumerate modules in process...\n");
	try {
		bMore = Module32First(hSnapshot, &fModule);
	}
	catch (...)
	{
		dwLastError = GetLastError();
		strErrorMessage = POC_Helper::strGetLastError(dwLastError);
		OutputDebugString((TEXT("[evil_POC] EnumLibW --> Module32First Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
		wprintf(L"\nfailed to enumerate modules. ErrorCode = 0x%x\n", dwLastError);
		printf(POC_Helper::GetLastErrorAsString().c_str());
		throw 2;
	}

	wprintf(L"Find target module in remote process...\n");
	for (; bMore; bMore = Module32Next(hSnapshot, &fModule))
	{
		//debug
		//wprintf(L"got module: %s\n", fModule.szModule);
		if (!_wcsicmp((LPCTSTR)fModule.szModule, szDllName) || !_wcsicmp((LPCTSTR)fModule.szExePath, szDllName))
		{
			//wprintf(L"\n[+] Module Found!!!\n");
			bFound = TRUE;
			break;
		}
	}

	//Clean up
	CloseHandle(hSnapshot);
	return bFound;
}

BOOL POC_EnumLib::EnumLibA(DWORD dwPID, PCSTR szDllName, MODULEENTRY32 &fModule) {

	OutputDebugString(TEXT("[evil_POC] EnumLibA -->"));

	//Allocate a (stack) buffer for the Unicode version of the pathname 
	SIZE_T cchSize = lstrlenA(szDllName) + 1;

	PWSTR pszDllNameW = (PWSTR)_alloca(cchSize * sizeof(wchar_t));

	//Convert the ANSI pathname to its Unicode equivalent 
	StringCchPrintfW(pszDllNameW, cchSize, L"%S", szDllName);

	//Call the Unicode version of the function to actually do the work. 
	return(EnumLibW(dwPID, pszDllNameW, fModule));
}

/* 
//// FIRST VERSION NOT STABLE
BOOL CheckDLL(DWORD dwPID, LPCTSTR szDllName, MODULEENTRY32 &fModule) {

	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot;

	// Get DLL_NAME in dwPID process with TH32CS_SNAPMODULE Parameter
	wprintf(L"Get process snapshot...\n");
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		wprintf(L"w> Fail\n");
		throw 1;
	}

	wprintf(L"Enumerate modules in process...\n");
	try {
		bMore = Module32First(hSnapshot, &fModule);
	}
	catch (...)
	{
		wprintf(L"\nfailed to enumerate modules. ErrorCode = 0x%x\n",GetLastError());
		printf(GetLastErrorAsString().c_str());
		throw 2;
	}

	wprintf(L"Find target module in remote process...\n");
	for (; bMore; bMore = Module32Next(hSnapshot, &fModule))
	{
		//debug
		//wprintf(L"got module: %S\n", fModule.szModule);
		if (!_tcsicmp((LPCTSTR)fModule.szModule, szDllName) || !_tcsicmp((LPCTSTR)fModule.szExePath, szDllName))
		{
			wprintf(L"\n[+]Module Found!!!\n");
			bFound = TRUE;
			break;
		}
	}

	//Clean up
	CloseHandle(hSnapshot);
	return bFound;
}
*/