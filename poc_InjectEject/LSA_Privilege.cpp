#pragma once

#include "LSA_Privilege.h"
#include <stdio.h>


BOOL InitLsaString(PLSA_UNICODE_STRING pLsaString, 	LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = lstrlenW(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}



PSID GetSIDFormProcess()
{
	HANDLE hToken = NULL;
	ULONG dwErrorCode = 0;
	DWORD dwBufferSize = 0;
	PTOKEN_USER pTokenUser = NULL;
	


	wprintf(L"\tRetrieve User SID from current process...\n");


	hToken = POC_Token::GetProcessToken();

	// Retrieve the token information in a TOKEN_USER structure.  
	TOKEN_INFORMATION_CLASS tok = TOKEN_INFORMATION_CLASS::TokenUser;
	GetTokenInformation(
		hToken,
		tok,      // Request for a TOKEN_USER structure.  
		NULL,
		0,
		&dwBufferSize
	);

	pTokenUser = (PTOKEN_USER) new BYTE[dwBufferSize];
	memset(pTokenUser, 0, dwBufferSize);
	if (GetTokenInformation(hToken,
		tok,
		pTokenUser,
		dwBufferSize,
		&dwBufferSize
	))
	{
		CloseHandle(hToken);
	}
	else
	{
		dwErrorCode = GetLastError();
		wprintf(L"w> GetTokenInformation failed. ErrorCode = 0x%d\n", dwErrorCode);
		throw HRESULT_FROM_WIN32(dwErrorCode);
	}

	//Validate SID
	if (IsValidSid(pTokenUser->User.Sid) == FALSE)
	{
		wprintf(L"w> The owner SID is invalid.\n");
		delete[] pTokenUser;
		throw MQ_ERROR;
	}

	return (pTokenUser->User.Sid);
}

/*Neme FORM SID

//validate SID
		DWORD dwSize = 256;
		LPWSTR lpName, lpDomain;
		DWORD myDwordNameLength = 0, myDwordDomLength = 0;
		SID_NAME_USE SidType;
		PSID getSid = new PSID;
		SID_NAME_USE myNameUse = SidTypeUnknown;

		//Make an initial lookup to find out how big the names are
		LookupAccountSid(
			NULL
			, getSid
			, NULL
			, (LPDWORD)&myDwordNameLength
			, NULL
			, (LPDWORD)&myDwordDomLength
			, &myNameUse
		);

		lpName = (LPWSTR)GlobalAlloc(GMEM_FIXED, myDwordNameLength * sizeof(wchar_t));
		lpDomain = (LPWSTR)GlobalAlloc(GMEM_FIXED, myDwordDomLength * sizeof(wchar_t));

		if (!LookupAccountSid(NULL, AccountSID,
			lpName, &dwSize, lpDomain,
			&dwSize, &SidType))
		{
			err = GetLastError();
			if (err == ERROR_NONE_MAPPED)
				wcscpy_s(lpName, _tcsclen(lpName), L"NONE_MAPPED");
			else
			{
				wprintf(L"w> LookupAccountSid Error %u\n", GetLastError());
				return FALSE;
			}
		}
		wprintf(L"Process user = %s\\%s\n",
			lpDomain, lpName);

*/

BOOL POC_LSA_Privilege::LSA_isPresentPrivilege(PCWSTR szPrivilege)
{
	BOOL bOk = FALSE;
	PSID AccountSID = NULL;
	DWORD SidSize;


	NTSTATUS stat;
	PLSA_UNICODE_STRING  pPrivs;
	LSA_OBJECT_ATTRIBUTES lsaOA = { 0 };
	LSA_HANDLE hPolicy;
	ULONG pPrivsCount = 0;
	ULONG err;
	
	__try {
		//get SID for loacl Administrator group
		wprintf(L"\tGet WinBuiltinAdministratorsSid...\n");

		// Allocate enough memory for the largest possible SID.
		SidSize = SECURITY_MAX_SID_SIZE;
		if (!(AccountSID = LocalAlloc(LMEM_FIXED, SidSize))) {
			wprintf(L"w> Fail LocalAlloc. ErrorCode = 0x%x\n", GetLastError());
			__leave;
		}

		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AccountSID, &SidSize)) {
			wprintf(L"w> Fail CreateWellKnownSid. ErrorCode = 0x%x\n", GetLastError());
			__leave;
		}

		wprintf(L"\tOpen LSA Policy...\n");
		stat = LsaOpenPolicy(NULL, &lsaOA, POLICY_LOOKUP_NAMES, &hPolicy);
		err = LsaNtStatusToWinError(stat);

		if (err != ERROR_SUCCESS) {
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", err);
			__leave;
		}
		err = 0;

		wprintf(L"\tEnumerate privileges...\n");
		stat = LsaEnumerateAccountRights(hPolicy, AccountSID, &pPrivs, &pPrivsCount);
		err = LsaNtStatusToWinError(stat);

		if (err != ERROR_SUCCESS) {
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", err);
			__leave;
		}
		err = 0;

		if (pPrivsCount != 0) {
			for (ULONG i = 0; i < pPrivsCount; i++) {

				//debug
				wprintf(L"\t\t%s\n", pPrivs[i].Buffer);

				if (_tcscmp(pPrivs[i].Buffer, szPrivilege) == 0) {
					//present
					wprintf(L"\n[+]User has privelege %s\n", szPrivilege);

					bOk = TRUE;

					break;
				}

			}
		}
		else 
			wprintf(L"\n[-]Failed to enum privileges");
		
	}
	
	__finally {
		//TODO clean up
		//LsaFreeMemory(pPrivs)
		//LsaClose($PolicyHandle)
		//FreeHGlobal(AccountSID)
	}


	return (bOk);

}

BOOL POC_LSA_Privilege::LSA_AddPrivilege(PCWSTR szPrivilege)
{
	BOOL bOk = FALSE;
	LSA_OBJECT_ATTRIBUTES lsaOA = { 0 };
	LSA_HANDLE hPolicy;
	NTSTATUS stat;
	LSA_UNICODE_STRING pPrivs;
	ULONG pPrivsCount = 0;
	PSID AccountSID;
	ULONG err = 0;
	DWORD SidSize;
	

	__try {

		//get SID for loacl Administrator group
		wprintf(L"\tGet WinBuiltinAdministratorsSid...\n");

		// Allocate enough memory for the largest possible SID.
		SidSize = SECURITY_MAX_SID_SIZE;
		if (!(AccountSID = LocalAlloc(LMEM_FIXED, SidSize))) {
			wprintf(L"w> Fail LocalAlloc. ErrorCode = 0x%x\n", GetLastError());
			__leave;
		}

		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AccountSID, &SidSize)) {
			wprintf(L"w> Fail CreateWellKnownSid. ErrorCode = 0x%x\n", GetLastError());
			__leave;
		}

		wprintf(L"\tOpen LSA Policy...\n");
		stat = LsaOpenPolicy(NULL, &lsaOA, POLICY_LOOKUP_NAMES, &hPolicy);
		err = LsaNtStatusToWinError(stat);

		if (err != ERROR_SUCCESS) {
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", err);
			__leave;
		}
		err = 0;
		
		wprintf(L"\tAdd privilege to the user...\n");

		// Create an LSA_UNICODE_STRING for the privilege names.
		if (!InitLsaString(&pPrivs, szPrivilege))
		{
			wprintf(L"w> Failed InitLsaString\n");
			__leave;
		}

		stat = LsaAddAccountRights(
			hPolicy,  // An open policy handle.
			AccountSID,    // The target SID.
			&pPrivs, // The privileges.
			1              // Number of privileges.
		);
		err = LsaNtStatusToWinError(stat);
		if (err != ERROR_SUCCESS) {
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", err);
			__leave;
		}
		err = 0;

		bOk = TRUE;
	}
	__finally {
		//TODO Clean up
		//LsaClose($PolicyHandle)
		//FreeHGlobal(AccountSID)
	}
	
	return (bOk);
}

BOOL POC_LSA_Privilege::LSA_RemovePrivilege(PCWSTR szPrivilege)
{
	BOOL bOk = FALSE;
	LSA_OBJECT_ATTRIBUTES lsaOA = { 0 };
	LSA_HANDLE hPolicy;
	NTSTATUS stat;
	LSA_UNICODE_STRING pPrivs;
	ULONG pPrivsCount = 0;
	PSID AccountSID;
	ULONG err = 0;
	DWORD SidSize;


	__try {

		//get SID for loacl Administrator group
		wprintf(L"\tGet WinBuiltinAdministratorsSid...\n");

		// Allocate enough memory for the largest possible SID.
		SidSize = SECURITY_MAX_SID_SIZE;
		if (!(AccountSID = LocalAlloc(LMEM_FIXED, SidSize))) {
			wprintf(L"w> Fail LocalAlloc. ErrorCode = 0x%x\n", GetLastError());
			__leave;
		}

		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AccountSID, &SidSize)) {
			wprintf(L"w> Fail CreateWellKnownSid. ErrorCode = 0x%x\n", GetLastError());
			__leave;
		}

		wprintf(L"\tOpen LSA Policy...\n");
		stat = LsaOpenPolicy(NULL, &lsaOA, POLICY_LOOKUP_NAMES, &hPolicy);
		err = LsaNtStatusToWinError(stat);

		if (err != ERROR_SUCCESS) {
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", err);
			__leave;
		}
		err = 0;

		wprintf(L"\tRemove privilege from the user...\n");

		// Create an LSA_UNICODE_STRING for the privilege names.
		if (!InitLsaString(&pPrivs, szPrivilege))
		{
			wprintf(L"w> Failed InitLsaString\n");
			__leave;
		}

		stat = LsaRemoveAccountRights(
			hPolicy,  // An open policy handle.
			AccountSID,    // The target SID.
			false,		// If TRUE, the function removes all privileges and deletes the account. In this case, the function ignores the UserRights parameter. If FALSE, the function removes the privileges specified by the UserRights parameter.
			&pPrivs, // The privileges.
			1              // Number of privileges.
		);
		err = LsaNtStatusToWinError(stat);
		if (err != ERROR_SUCCESS) {
			wprintf(L"w> Fail. ErrorCode = 0x%x\n", err);
			__leave;
		}
		err = 0;

		bOk = TRUE;
	}
	__finally {
		//TODO Clean up
		//LsaClose($PolicyHandle)
		//FreeHGlobal(AccountSID)
	}

	return (bOk);
}