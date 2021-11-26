// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		OutputDebugString(TEXT("[evilDLL_reflected] PROCESS_ATTACH"));
		//Sleep(30000);
		break;
    case DLL_THREAD_ATTACH:
		OutputDebugString(TEXT("[evilDLL_reflected] THREAD_ATTACH"));
		//Sleep(30000);
		break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

