#pragma once

#include <conio.h>
#include "Helper.h"

using namespace std;

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
string POC_Helper::GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

LPCTSTR POC_Helper::strGetLastError(DWORD dwError) {
	LPCTSTR strErrorMessage = NULL;

	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL,
		dwError,
		0,
		(LPWSTR)&strErrorMessage,
		0,
		NULL);

	return strErrorMessage;
}

BOOL POC_Helper::isNumber(char number[])
{
	int i = 0;

	//checking for negative numbers
	if (number[0] == '-')
		i = 1;
	for (; number[i] != 0; i++)
	{
		//if (number[i] > '9' || number[i] < '0')
		if (!isdigit(number[i]))
			return false;
	}
	return true;
}

VOID POC_Helper::ShowHelp()
{
	wprintf(TEXT("Usage:\n"));
	wprintf(TEXT("      -i <process name> <path/to/dll>\tInject Dll into the process\n"));
	wprintf(TEXT("      -h <process name> <path/to/dll>\tInject Dll via SetWindowsHookEx (exported func = poc)\n"));
	wprintf(TEXT("      -u <process name> <dll name>\tUnload Dll from the process\n"));
	wprintf(TEXT("      -c <process name> <dll name>\tCheck Dll loaded by the process\n"));
	wprintf(TEXT("      -e <process name to duplicate Token> <path/to/exeToRun>\tRun Elevated process via DuplicateTokenEx\n\n"));
	wprintf(TEXT("evillDll.dll Usage:\n"));
	wprintf(TEXT("  config file location: c:\\logs\\evil.conf\n\n"));
	wprintf(TEXT("      default action killProcessByName (snsrv.exe)\n"));
	wprintf(TEXT("  Possible config record:\n"));
	wprintf(TEXT("      killProcessByName\n"));
	wprintf(TEXT("      <process name>\n\n"));
	wprintf(TEXT("      StopService\n"));
	wprintf(TEXT("      <service name>\n\n"));
	wprintf(TEXT("      SetServiceType_DISABLE\n"));
	wprintf(TEXT("      <service name>\n\n"));
	wprintf(TEXT("      InjectLib\n"));
	wprintf(TEXT("      <process name>\n"));
	wprintf(TEXT("      <path/to/dll>\n\n"));
	wprintf(TEXT("      RenameFile\n"));
	wprintf(TEXT("      <old file path>\n"));
	wprintf(TEXT("      <new file path>\n\n"));
	wprintf(TEXT("      MessageBox\n"));
	wprintf(TEXT("      <process name>\n\n")); 
	wprintf(TEXT("      StartHollowed\n"));
	wprintf(TEXT("      <orig exe path>\n"));
	wprintf(TEXT("      <hollow exe path>\n\n"));
	wprintf(TEXT("      NTkillProcessByName\n"));
	wprintf(TEXT("      <process name>\n\n"));
	wprintf(TEXT("      RemoveAllPrivileges\n"));
	wprintf(TEXT("      <process name>\n\n"));

}


POC_Helper::ConfigInfo POC_Helper::readFile(PCWSTR filename)
{	
	OutputDebugString((TEXT("[evil_POC] readFile --> fileName = ") + (wstring) filename).c_str());
	std::wifstream file_in(filename);
	file_in.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));

	//cout << file_in.rdbuf(); // debug

	wstring Operation = TEXT("default");
	wstring Object = TEXT("default");
	wstring reflectDll = TEXT("default");
	map<std::wstring, std::wstring> my_map;

	std::getline(file_in, Operation);
	std::getline(file_in, Object);
	std::getline(file_in, reflectDll);
	//wcout << "Debug: key = " << Operation << " value = " << Object << endl; // No output!?!?

	OutputDebugString((TEXT("[evil_POC] readFile --> Operation = ") + Operation).c_str());
	OutputDebugString((TEXT("[evil_POC] readFile --> Object = ") + Object).c_str());
	OutputDebugString((TEXT("[evil_POC] readFile --> reflectDll = ") + reflectDll).c_str());

	my_map[TEXT("operation")] = Operation;
	my_map[TEXT("object")] = Object;
	my_map[TEXT("reflectDll")] = reflectDll;

	file_in.close();

	return my_map;
}

void POC_Helper::writeFile(PCWSTR szDestPath, PCWSTR szText) {
	try {
		wofstream myfile;
		myfile.open(szDestPath);
		myfile << szText;
		myfile.close();
		OutputDebugString(TEXT("[evil_POC] Echo --> SUCCESS"));
	}
	catch (...) {
		OutputDebugString(TEXT("[evil_POC] Echo --> FAIL"));
	}
}

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
	pPROCESSENUM s;
	s = (pPROCESSENUM)lParam;
	DWORD lpdwProcessId;
	GetWindowThreadProcessId(hwnd, &lpdwProcessId);
	if (lpdwProcessId == s->dwProcessID)
	{
		//s->hInfo.UniqueThread = hwnd;
		s->hInfo.UniqueProcess = (PDWORD)lpdwProcessId;
		return FALSE;
	}
	return TRUE;
}

//	Вспомогательная функция, для удалленой отладки программы 
//	(в смысле в этой функции я останавливаюсь и жду нажатия какой-нибудь клавиши
//	чтобы можно было подключиться отладчиком к моей программе)
//
void wait_for_remote_debug_interactive()
{
#pragma warning(disable: 6031) // Return value ignored: '_getch'
	printf("Hit any key to continue execution...\n");
	_getch();
#pragma warning(default: 6031)
}


void wait_for_remote_debug()
{
	OutputDebugString(TEXT("Wait debugger..."));
	while (!::IsDebuggerPresent())
		::Sleep(100);

	OutputDebugString(TEXT("Got debugger connected!"));
}