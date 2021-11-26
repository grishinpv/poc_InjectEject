#pragma once

#include "EjectLib.h"
#include "EnumLib.h"
#include "Helper.h"

BOOL POC_EjectLib::EjectLibW(DWORD dwPID, PCWSTR szDllName)
{
	OutputDebugString(TEXT("[evil_POC] EjectLibW -->"));

	BOOL bOk = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	PTHREAD_START_ROUTINE pThreadProc;
	MODULEENTRY32 fModule = { sizeof(fModule) };
	LPCTSTR strErrorMessage = NULL;
	DWORD dwLastError = 0;

	try {
		if (!POC_EnumLib::EnumLib(dwPID, szDllName, fModule))
		{
			OutputDebugString(TEXT("[evil_POC] EjectLibW --> Module not found. Skip unload"));
			wprintf(L"[-]Module not found. Skip unload\n");
			//__leave;
			return bOk;
		}


		wprintf(L"Opening target process...\n");
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, dwPID);
		if (hProcess == NULL) {
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] EjectLibW --> OpenProcess Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//wprintf(L"LastError: %s\n", GetLastErrorAsString().c_str());
			//__leave;
			return bOk;
		}


		wprintf(L"Get FreeLibraryAndExitThread in kernel32.dll...\n");
		//pThreadProc = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(TEXT("kernel32.dll")), "FreeLibraryAndExitThread");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(TEXT("kernel32.dll")), "FreeLibrary");
		if (pThreadProc == NULL) {
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] EjectLibW --> GetProcAddress Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOk;
		}

		wprintf(L"Creating remote thread...\n");
		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, fModule.modBaseAddr, 0, NULL);
		if (hThread == NULL) {
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] EjectLibW --> CreateRemoteThread Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOk;
		}

		wprintf(L"Wait for FreeLibraryAndExitThread complete...\n");
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE;
	}
	catch (...) {
		OutputDebugString(TEXT("[evil_POC] EjectLibW --> EXCEPTION"));
	}
	//__finally {
		if (hThread != NULL) {
			CloseHandle(hThread);
		}

		if (hProcess != NULL) {
			CloseHandle(hProcess);
		}
	//}

	return (bOk);
}

BOOL POC_EjectLib::EjectLibA(DWORD dwProcessId, PCSTR pszLibFile) {
	
	OutputDebugString(TEXT("[evil_POC] EjectLibA -->"));

	//Allocate a (stack) buffer for the Unicode version of the pathname 
	SIZE_T cchSize = lstrlenA(pszLibFile) + 1;

	PWSTR pszLibFileW = (PWSTR)_alloca(cchSize * sizeof(wchar_t));

	//Convert the ANSI pathname to its Unicode equivalent 
	StringCchPrintfW(pszLibFileW, cchSize, L"%S", pszLibFile);

	//Call the Unicode version of the function to actually do the work. 
	return(EjectLibW(dwProcessId, pszLibFileW));

}