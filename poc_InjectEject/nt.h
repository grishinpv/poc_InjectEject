#pragma once

#include <windows.h>
#include <ntstatus.h>



NTSTATUS NTAPI NtSetInformationToken(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength
);

NTSTATUS NTAPI RtlInitializeSid(
	_Out_ PSID Sid,
	_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	_In_ UCHAR SubAuthorityCount
);


NTSTATUS NTAPI NtFilterToken(
	_In_ HANDLE ExistingTokenHandle,
	_In_ ULONG Flags,
	_In_opt_ PTOKEN_GROUPS SidsToDisable,
	_In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
	_In_opt_ PTOKEN_GROUPS RestrictedSids,
	_Out_ PHANDLE NewTokenHandle
);

NTSTATUS NTAPI RtlInitializeSid(
	_Out_ PSID Sid,
	_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	_In_ UCHAR SubAuthorityCount
);


PULONG NTAPI RtlSubAuthoritySid(
	_In_ PSID Sid,
	_In_ ULONG SubAuthority
);