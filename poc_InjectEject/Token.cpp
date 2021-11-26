#pragma once


#include "Token.h"
//#include <ntifs.h>
//#include <ntsecapi.h>
namespace poc {
	//#include <winnt.h>
	#include <winternl.h>
	#include <ntstatus.h>
}
//#include "nt.h"

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, PHANDLE NewTokenHandle);
EXTERN_C NTSTATUS NTAPI NtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength);

HANDLE POC_Token::GetProcessToken(DWORD dwPID)
{
	HANDLE hProcess;
	HANDLE hToken;
	ULONG dwErrorCode = 0;

	if (dwPID == 0) {
		wprintf(L"Opening current process...\n");
		hProcess = GetCurrentProcess();
	}
	else {
		wprintf(L"Opening process...%d\n", dwPID);
		//query info
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
	}
	// Open the access token associated with the calling process.
	// work wih TOKEN_QUERY previous
	if (OpenProcessToken(
		hProcess,
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken
	) == FALSE)
	{
		dwErrorCode = GetLastError();
		wprintf(L"w> OpenProcessToken failed. ErrorCode = 0x%d\n", dwErrorCode);
		OutputDebugString(L"w> GetProcessToken::OpenProcessToken failed");
		throw HRESULT_FROM_WIN32(dwErrorCode);
	}

	return hToken;
}

/*
std::vector<LPWSTR> POC_Token::TokenPrivilegesToString(PTOKEN_PRIVILEGES *pTokenPriv) {
	ULONG dwErrorCode = 0;
	PLUID pLUID = NULL;
	LPWSTR  lpPrivName;
	DWORD sz = 0;

	//iterate over privileges
	if (pTokenPriv->PrivilegeCount == 0) {
		wprintf(L"w> TokenPrivileges PrivilegeCount = 0\n");
		throw HRESULT_FROM_WIN32(dwErrorCode);
	}
	else
	{
		wprintf(L"\tPrivilegeCount = %d\n", pTokenPriv->PrivilegeCount);


	}

	std::vector<LPWSTR> lpwstrArray(pTokenPriv->PrivilegeCount);

	for (size_t i = 0; i < pTokenPriv->PrivilegeCount; i++) {
		sz = 0;
		LUID g = pTokenPriv->Privileges[i].Luid;
		LookupPrivilegeName(NULL, g, NULL, &sz);
		lpPrivName = (LPTSTR)malloc(sz * sizeof(TCHAR));

		//LPWSTR name;
		if (!LookupPrivilegeName(NULL, &(pTokenPriv->Privileges[i].Luid), lpPrivName, &sz)) {
			dwErrorCode = GetLastError();
			wprintf(L"w> GetTokenInformation failed. ErrorCode = 0x%d\n", dwErrorCode);
			throw HRESULT_FROM_WIN32(dwErrorCode);
		}

		lpwstrArray[i] = const_cast<wchar_t*>(lpPrivName);

		//FIND
		///*
		if (0 == ::lstrcmp(name, SE_SYSTEMTIME_NAME)) {
			bOk = TRUE;
			wprintf(L"Found Privilege = %d", name);
		}
		// tcout << name << std::endl;
		//
		*


		//debug
		wprintf(L"\t\t%s\n", lpPrivName);

		//free(name);



	}


	return lpwstrArray;

}
*/
BOOL POC_Token::GetPrivilegesFromProcess(PTOKEN_PRIVILEGES *pTokenPriv, DWORD dwPID)
{
	BOOL bOk = FALSE;
	HANDLE hToken = NULL;
	ULONG dwErrorCode = 0;
	DWORD dwBufferSize = 0;
	//PTOKEN_PRIVILEGES pTokenPriv = NULL;
	PLUID pLUID = NULL;
	LPWSTR  lpPrivName;
	DWORD sz = 0;


	wprintf(L"\tRetrieve User Privileges from process...\n");

	hToken = POC_Token::GetProcessToken(dwPID);

	// Retrieve the token information in a TOKEN_PRIVILEGES structure.  
	GetTokenInformation(
		hToken,
		TokenPrivileges,      // Request for a TOKEN_PRIVILEGES structure.  
		NULL,
		0,
		&dwBufferSize
	);

	*pTokenPriv = (PTOKEN_PRIVILEGES) new BYTE[dwBufferSize];
	memset(*pTokenPriv, 0, dwBufferSize);
	if (GetTokenInformation(hToken,
		TokenPrivileges,
		*pTokenPriv,
		dwBufferSize,
		&dwBufferSize
	))
	{
		CloseHandle(hToken);
		bOk = TRUE;
	}
	else
	{
		dwErrorCode = GetLastError();
		wprintf(L"w> GetTokenInformation failed. ErrorCode = 0x%d\n", dwErrorCode);
		OutputDebugString(L"w> GetPrivilegesFromProcess::GetTokenInformation failed");
		throw HRESULT_FROM_WIN32(dwErrorCode);
	}

	


	return (bOk);

}

BOOL POC_Token::RemovePrivilegesFromProcess(PTOKEN_PRIVILEGES pTokenPriv, DWORD dwPID)
{
	BOOL bOk = FALSE;
	HANDLE hToken = NULL;
	ULONG dwErrorCode = 0;
	DWORD dwBufferSize = 0;
	//PTOKEN_PRIVILEGES pTokenPriv = NULL;
	PLUID pLUID = NULL;
	LPWSTR  lpPrivName;
	DWORD sz = 0;
	HANDLE newTokenHandle;
	NTSTATUS status;
	PSID lowMandatoryLevelSid;
	UCHAR lowMandatoryLevelSidBuffer[FIELD_OFFSET(SID, SubAuthority) + sizeof(ULONG)];
	TOKEN_MANDATORY_LABEL mandatoryLabel;
	const DWORD size = 10000 + 1;
	WCHAR buffer[size];

	static SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	static SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;

	wprintf(L"\tRetrieve User Privileges from current process...\n");

	hToken = POC_Token::GetProcessToken(dwPID);

	
	
	if (!AdjustTokenPrivileges(
					hToken,
					TRUE,
					NULL,
					0,
					NULL,
					0)) {
	
		dwErrorCode = GetLastError();
		wprintf(L"w> AdjustTokenPrivileges failed. ErrorCode = 0x%d\n", dwErrorCode);
		OutputDebugString(L"w> GetPrivilegesFromProcess::AdjustTokenPrivileges failed");
		return (bOk);

	}
	else {
		bOk = TRUE;

	}

	// Set the integrity level to Low if we're on Vista and above.
	/*
	lowMandatoryLevelSid = (PSID)lowMandatoryLevelSidBuffer;
	InitializeSid(lowMandatoryLevelSid, &mandatoryLabelAuthority, 1);
	*GetSidSubAuthority(lowMandatoryLevelSid, 0) = SECURITY_MANDATORY_LOW_RID;

	mandatoryLabel.Label.Sid = lowMandatoryLevelSid;
	mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;

	if (!SetTokenInformation(
		newTokenHandle,
		TokenIntegrityLevel,
		&mandatoryLabel,
		sizeof(TOKEN_MANDATORY_LABEL))) {

		//status = NtSetInformationToken(newTokenHandle, TokenIntegrityLevel, &mandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL));

		dwErrorCode = GetLastError();
		wprintf(L"w> NtSetInformationToken failed. ErrorCode = 0x%d\n", dwErrorCode);
		return (bOk);
	}
	*/
	return (bOk);
	
}