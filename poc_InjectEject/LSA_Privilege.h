#pragma once
#include <windows.h>
#include <ntsecapi.h>
#include <tchar.h>
#include <Mq.h>
#include <vector>
#include <winnt.h>
#include "Token.h"




class POC_LSA_Privilege {
public:
	POC_LSA_Privilege();
	static BOOL LSA_AddPrivilege(PCWSTR szPrivilege);
	static BOOL LSA_isPresentPrivilege(PCWSTR szPrivilege);
	static BOOL LSA_RemovePrivilege(PCWSTR szPrivilege);
};
