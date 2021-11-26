// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the EVILDLLREFLECTED_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// EVILDLLREFLECTED_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef EVILDLLREFLECTED_EXPORTS
#define EVILDLLREFLECTED_API __declspec(dllexport)
#else
#define EVILDLLREFLECTED_API __declspec(dllimport)
#endif


extern "C" EVILDLLREFLECTED_API int nevilDllreflected;

EVILDLLREFLECTED_API int fnevilDllreflected(void);
