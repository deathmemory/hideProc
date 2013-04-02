#include "StdAfx.h"
#include "HOOK.h"
#include "../Detours/detours.h"
#include "../publicdef/processhelper.hpp"

static DWORD g_dwSelfProcessID  = 4376;
lpZwQuerySystemInformation g_ZwQuerySystemInformation = NULL;
lpCreateFileW g_lpCreateFileW = NULL;
lpRegQueryValueExW g_lpRegQueryValueExW = NULL;
void InstallHook()
{
	DWORD dwPid = ProcessHelper::ScanProcess(_T("MK.exe"));
	g_dwSelfProcessID = dwPid;
	if ( 0 == g_dwSelfProcessID )
	{
		MessageBoxA(0, "please run mk first!", 0, 0);
		return;
	}
	HMODULE hMoudle = LoadLibrary(_T("Ntdll.dll"));
	if (hMoudle)
	{
		g_ZwQuerySystemInformation = (lpZwQuerySystemInformation)GetProcAddress(hMoudle, "ZwQuerySystemInformation");
		if ( !g_ZwQuerySystemInformation )
		{
			MessageBoxA(0, "not found ZwQuerySystemInformation", 0, 0);
			return;
		}
	}
	hMoudle = LoadLibrary(_T("Kernel32.dll"));
	if (hMoudle)
	{
		g_lpCreateFileW = (lpCreateFileW)GetProcAddress(hMoudle, "CreateFileW");
		if ( ! g_lpCreateFileW )
		{
			MessageBoxA(0, "not found CreateFileW", 0, 0);
			return;
		}
	}
	hMoudle = LoadLibrary(_T("Advapi32.dll"));
	if (hMoudle)
	{
		g_lpRegQueryValueExW = (lpRegQueryValueExW)GetProcAddress(hMoudle, "RegQueryValueExW");
		if ( ! g_lpRegQueryValueExW )
		{
			MessageBoxA(0, "not found RegQueryValueExW", 0, 0);
			return;
		}
	}
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID *)&g_ZwQuerySystemInformation, ZwQuerySystemInformationFack);
	DetourAttach((PVOID *)&g_lpCreateFileW, CreateFileWFack);
	DetourAttach((PVOID *)&g_lpRegQueryValueExW, RegQueryValueExWFack);
	if(DetourTransactionCommit() == NO_ERROR)
		MessageBoxA(0, "success!\r\nplease press ok", 0, 0);
}

NTSTATUS WINAPI ZwQuerySystemInformationFack(
	__in          DWORD SystemInformationClass,
	__in	      PVOID SystemInformation,
	__in          ULONG SystemInformationLength,
	__out_opt     PULONG ReturnLength
	)
{
  long Result = 0;

  Result = (long)(g_ZwQuerySystemInformation)(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);

  //一定要使用结构化异常处理，否则就有可能出现异常对话框。
  __try
  {
    if(SystemInformationClass == 5 && Result == 0 /* STATUS_SUCCESS */)
    {
      PSYSTEM_PROCESSES pProcessInfo;
      PSYSTEM_PROCESSES pPrevProcessInfo;

      pProcessInfo = (PSYSTEM_PROCESSES)SystemInformation;
      pPrevProcessInfo = pProcessInfo;

      while(true)
      {
        if(pProcessInfo != NULL && pProcessInfo->ProcessId == g_dwSelfProcessID)
        {
			MessageBoxA(0, "pid mat!", 0, 0);
          if(pProcessInfo->NextEntryDelta == 0)
            pPrevProcessInfo->NextEntryDelta = 0;
          else
            pPrevProcessInfo->NextEntryDelta = pPrevProcessInfo->NextEntryDelta + pProcessInfo->NextEntryDelta;

          break;
        }

        if(pProcessInfo->NextEntryDelta == 0)
          break;

        pPrevProcessInfo = pProcessInfo;
        pProcessInfo = (PSYSTEM_PROCESSES)((char*)pProcessInfo + pProcessInfo->NextEntryDelta);
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    // 发生异常，但是不必做任何事
    ::MessageBoxA(NULL,"Exception Occured at self-defined function :(",NULL,MB_OK | MB_ICONWARNING);
    //*/
  }

  return Result;
}
//---------------------------------------------------------------------------

HANDLE WINAPI CreateFileWFack(
							  __in          LPCTSTR lpFileName,
							  __in          DWORD dwDesiredAccess,
							  __in          DWORD dwShareMode,
							  __in          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
							  __in          DWORD dwCreationDisposition,
							  __in          DWORD dwFlagsAndAttributes,
							  __in          HANDLE hTemplateFile
							  )
{
	if( StrStrI(lpFileName, _T("mk")) )
	{
		SetLastError(ERROR_FILE_NOT_FOUND);
		return INVALID_HANDLE_VALUE;
	}

	if (g_lpCreateFileW)
		return g_lpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	else
		return INVALID_HANDLE_VALUE;
}

LONG WINAPI RegQueryValueExWFack(
								 __in          HKEY hKey,
								 __in          LPCTSTR lpValueName,
								 LPDWORD lpReserved,
								 __out         LPDWORD lpType,
								 __out         LPBYTE lpData,
								 __in      LPDWORD lpcbData
								 )
{
	if( StrStrI(lpValueName, _T("mk")) )
		return ERROR_PATH_NOT_FOUND;
	return g_lpRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}