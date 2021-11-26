#pragma once
#include <Windows.h>
#include <iostream>

#include <sstream>
#include <fstream>
#include <codecvt>

#include <map>
//#include <string>
//#include <iostream>
//#include <vector>
namespace poc {
#include <winternl.h>
}


typedef struct _PROCESSENUM
{
	poc::CLIENT_ID hInfo{};
	DWORD dwProcessID;
} PROCESSENUM, *pPROCESSENUM;

void wait_for_remote_debug();
void wait_for_remote_debug_interactive();

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam);

class POC_Helper {
public:
	POC_Helper();
	typedef std::map<std::wstring, std::wstring> ConfigInfo;

	static std::string GetLastErrorAsString();
	static VOID ShowHelp();
	static ConfigInfo readFile(PCWSTR filename);
	static LPCWSTR strGetLastError(DWORD dwError);
	static BOOL isNumber(char number[]);
	static void writeFile(PCWSTR szDestPath, PCWSTR szText);
	
};