#pragma once

#include <Windows.h>

BOOL StopService(PCWSTR szProcessName);
BOOL killProcessByName(PCWSTR szProcessName);
BOOL SetServiceType_DISABLE(PCWSTR szProcessName);
