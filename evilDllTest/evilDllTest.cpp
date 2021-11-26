// evilDllTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once
#include <iostream>

#include "..\poc_InjectEject\Helper.h"
//#include "..\poc_InjectEject\fProcess.h"
//#include "..\poc_InjectEject\LSA_Privilege.h"

#include <ntstatus.h>
namespace poc
{
#include <winternl.h>
}
//#include <ntdef.h>
//#include <ntddk.h>

#include <conio.h>
#include <Windows.h>

/* disabled for evil dll.load
#pragma comment(lib,"ntdll.lib")


typedef  poc::CLIENT_ID *PCLIENT_ID;

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
EXTERN_C NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, poc::POBJECT_ATTRIBUTES, PCLIENT_ID);

*/

using namespace std;

BOOL __LoadLibrary(LPCWSTR dllName, HINSTANCE *hGetProcIDDLL) {
	LPCTSTR strErrorMessage = NULL;
	BOOL bRes = true;

	*hGetProcIDDLL = LoadLibrary(dllName);
	if (*hGetProcIDDLL == NULL) {
		strErrorMessage = POC_Helper::strGetLastError(GetLastError());
		cout << "[-] LoadLibrary \""; wcout << dllName; cout << "\" status = FAILED Error = " << POC_Helper::GetLastErrorAsString() << endl;
		OutputDebugString((TEXT("[poc] LoadLibrary status = FAILED ErrorCode = 0x") + (std::wstring)strErrorMessage).c_str());
		bRes = false;
		return bRes;
	}

	cout << "[+] LoadLibrary \""; wcout << dllName; cout << endl;
	OutputDebugString(TEXT("[poc] LoadLibrary status = SUCCESS"));

	return bRes;
}

int main()
{
	

	//wait_for_remote_debug_interactive();
	//if (POC_LSA_Privilege::LSA_AddPrivilege(SE_DEBUG_NAME)) 
	//POC_fProcess::RemoveAllPrivileges(L"snfdesrv.exe");
	//POC_fProcess::NTkillProcessByName(L"snicon.exe");

	HINSTANCE hGetProcIDDLL = NULL;
	

	int ch = 0;
	while (ch != 0x1B) {
		_cputs("Press <AnyKey> to repeat. Press <Esc> to Exit...\n");
		if (!__LoadLibrary(TEXT("evilDll.dll"), &hGetProcIDDLL)) {
			return false;
		}
		ch = _getch();
		if (ch == 0x1B)
			break;
		if (hGetProcIDDLL) {
			FreeLibrary(hGetProcIDDLL);
		}
	}
	


	
}
